import argparse
import json
import pathlib
import sys
from rights_graph.primitives import GraphError, canonical, fields, json_loads, reject
from rights_graph.service import RightsService
from rights_graph.catalog import importing, linting
from rights_graph.planner import plans, builds, artifacts, inspection, recovery


def read_json(path, *, maximum=16777216):
    if path == '-':
        raw = sys.stdin.read(maximum + 1)
    else:
        source = pathlib.Path(path)
        if source.stat().st_size > maximum:
            reject('input_size', 'Input file exceeds maximum supported size')
        raw = source.read_text(encoding='utf-8')
    if len(raw.encode('utf-8')) > maximum:
        reject('input_size', 'Input content exceeds maximum supported size')
    return json_loads(raw)


def write_json(value, output=None):
    text = canonical(value) + '\n'
    if output is None or output == '-':
        sys.stdout.write(text)
        return
    path = pathlib.Path(output)
    if path.exists():
        reject('output_exists', 'Output path exists; choose a new path')
    with path.open('x', encoding='utf-8') as stream:
        stream.write(text)


def parser():
    root = argparse.ArgumentParser(prog='rights-graph', description='Offline column lineage and authorization compiler')
    root.add_argument('--db', default='rights.sqlite3')
    root.add_argument('--output')
    sub = root.add_subparsers(dest='command', required=True)
    call = sub.add_parser('call', help='Execute one structured service operation')
    call.add_argument('operation')
    call.add_argument('--input', required=True)
    transaction = sub.add_parser('transaction', help='Execute an atomic list of service operations')
    transaction.add_argument('--input', required=True)
    stream = sub.add_parser('stream', help='Execute newline-delimited requests; each line is an independent transaction')
    stream.add_argument('--input', required=True)
    stream.add_argument('--stop-on-error', action='store_true')
    load = sub.add_parser('import-catalog')
    load.add_argument('--input', required=True)
    sub.add_parser('export-catalog')
    plan = sub.add_parser('plan')
    plan.add_argument('target')
    plan.add_argument('--context', required=True)
    plan.add_argument('--columns', nargs='+')
    build = sub.add_parser('build')
    build.add_argument('plan_id')
    build.add_argument('--build-id', required=True)
    build.add_argument('--owner', default='cli-worker')
    verify = sub.add_parser('verify-artifact')
    verify.add_argument('artifact_id')
    verify.add_argument('--context')
    export = sub.add_parser('export-artifact')
    export.add_argument('artifact_id')
    export.add_argument('--context')
    preview = sub.add_parser('preview')
    preview.add_argument('plan_id')
    preview.add_argument('--bindings', required=True)
    preview.add_argument('--limit', type=int, default=10000)
    lint = sub.add_parser('lint')
    lint.add_argument('--context', required=True)
    graph = sub.add_parser('column-graph')
    graph.add_argument('target')
    consumers = sub.add_parser('column-consumers')
    consumers.add_argument('asset_id')
    consumers.add_argument('column')
    sub.add_parser('check')
    sub.add_parser('overview')
    sub.add_parser('recovery-queue')
    demo = sub.add_parser('demo')
    demo.add_argument('--fixture', required=True)
    return root


def execute_stream(service, path, stop_on_error=False):
    source = sys.stdin if path == '-' else pathlib.Path(path).open(encoding='utf-8')
    results = []
    failed = 0
    try:
        for number, raw in enumerate(source, 1):
            if number > 10000:
                reject('stream_size', 'Request stream exceeds maximum number of lines')
            if len(raw.encode('utf-8')) > 1048576:
                reject('stream_line_size', 'Request line exceeds maximum size', line=number)
            if not raw.strip():
                continue
            try:
                value = json_loads(raw)
                fields(value, {'operation', 'arguments'})
                with service.store.atomic():
                    result = service.dispatch(value['operation'], value['arguments'])
                results.append({'line': number, 'ok': True, 'result': result})
            except GraphError as exc:
                failed += 1
                results.append({'line': number, 'ok': False, 'error': exc.json()})
                if stop_on_error:
                    break
    finally:
        if source is not sys.stdin:
            source.close()
    return {'results': results, 'failed': failed, 'succeeded': len(results) - failed}


def demonstrate(service, fixture):
    fields(fixture, {'catalog', 'context', 'target', 'batches', 'bindings', 'revoke_grant'})
    importing.import_catalog(service.store, fixture['catalog'])
    for batch in fixture['batches']:
        service.preview.data.import_rows(**batch)
    plan = plans.create(service.store, fixture['target'], fixture['context'])
    builds.create(service.store, 'demo-build', plan['plan_id'])
    token = builds.claim(service.store, 'demo-build', 'demo-worker')
    first = builds.run_step(service.store, 'demo-build', token)
    visible_before = artifacts.listing(service.store)
    if visible_before:
        reject('demo_atomicity', 'Unfinished build unexpectedly published artifacts')
    while not first['finished']:
        first = builds.run_step(service.store, 'demo-build', token)
    completed = builds.finalize(service.store, 'demo-build', token)
    target = completed['result']['target_artifact']
    preview = service.preview.run(plan['plan_id'], fixture['bindings'])
    exported = service.preview.export(preview['preview_id'], target)
    proof = artifacts.verify_export(exported['authorization'])
    if not proof['integrity'] or not proof['declared_context_allowed']:
        reject('demo_attestation', 'Exported attestation verification failed')
    from rights_graph.policy import grants
    grant = grants.get(service.store, fixture['revoke_grant'])
    grants.revoke(service.store, grant['grant_id'], grant['revision'], 'Synthetic source withdrawal')
    invalidated = artifacts.verify(service.store, target)
    if invalidated['valid']:
        reject('demo_revocation', 'Revocation failed to invalidate derived artifact')
    check = inspection.check(service.store)
    if not check['ok']:
        reject('demo_integrity', 'Demonstration database failed integrity checks', check=check)
    return {'synthetic': True, 'target': fixture['target'], 'rows': preview['payload']['rows'], 'row_lineage': preview['payload']['row_lineage'], 'manifest_sha256': exported['authorization']['sha256'], 'uncommitted_artifacts': len(visible_before), 'revocation_blocked_export': not invalidated['valid'], 'integrity': check['ok']}


def run(args, service):
    command = args.command
    if command == 'call':
        return service.dispatch(args.operation, read_json(args.input))
    if command == 'transaction':
        return service.transaction(read_json(args.input))
    if command == 'stream':
        return execute_stream(service, args.input, args.stop_on_error)
    if command == 'import-catalog':
        return importing.import_catalog(service.store, read_json(args.input))
    if command == 'export-catalog':
        return importing.export_catalog(service.store)
    if command == 'plan':
        return plans.create(service.store, args.target, read_json(args.context), columns=args.columns)
    if command == 'build':
        builds.create(service.store, args.build_id, args.plan_id)
        return builds.execute(service.store, args.build_id, args.owner)
    if command == 'verify-artifact':
        return artifacts.verify(service.store, args.artifact_id, read_json(args.context) if args.context else None)
    if command == 'export-artifact':
        return artifacts.export(service.store, args.artifact_id, read_json(args.context) if args.context else None)
    if command == 'preview':
        return service.preview.run(args.plan_id, read_json(args.bindings), limit=args.limit)
    if command == 'lint':
        return linting.lint(service.store, read_json(args.context))
    if command == 'column-graph':
        return linting.column_graph(service.store, args.target)
    if command == 'column-consumers':
        return linting.consumers_of_column(service.store, args.asset_id, args.column)
    if command == 'check':
        return service.dispatch('system.check', {})
    if command == 'overview':
        return inspection.overview(service.store)
    if command == 'recovery-queue':
        return recovery.queue(service.store)
    if command == 'demo':
        return demonstrate(service, read_json(args.fixture))
    reject('unknown_command', 'Unsupported command')


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        with RightsService(args.db) as service:
            result = run(args, service)
        write_json(result, args.output)
        if args.command == 'stream' and result['failed']:
            return 2
        if args.command in {'check', 'lint'} and not result['ok']:
            return 2
        if args.command == 'verify-artifact' and not result['valid']:
            return 2
        return 0
    except GraphError as exc:
        sys.stderr.write(canonical({'ok': False, 'error': exc.json()}) + '\n')
        return 2
    except (OSError, UnicodeError) as exc:
        sys.stderr.write(canonical({'ok': False, 'error': {'code': 'io_failure', 'message': str(exc)}}) + '\n')
        return 3
