# 授权数据图

管理源资产、派生配方、列级血缘和用途地域授权，按授权上下文预览、构建并交付数据产品。撤权会影响计划和成品有效性。

演练使用本地目录与数据批次完成授权规划、构建和校验。预览连接按等长位置对齐；本地证明不是外部签名。

主要代码位于 rights_graph，按 catalog、policy、planner、journal 划分职责；tests 保存领域行为、边界及存储回归用例。命令接收严格 JSON，详细操作名与字段可通过对应帮助入口及 service 中的注册表查询。示例中的机构、客户、案件和测量均为本地合成记录，不涉及真实个人资料。

使用 Python 3.11.2 与标准库，无第三方包。运行无需访问外部服务或提供账号。依赖清单 requirements.txt 为空，.python-version 固定解释器版本。

在项目根目录运行：

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q rights_graph
python3 -m rights_graph --db :memory: demo --fixture fixtures/demo.json
python3 -m rights_graph --db :memory: drift-demo --fixture fixtures/drift_demo.json
```

分布漂移诊断（rights_graph/diagnostics，服务操作 drift.analyze、drift.get、drift.export、drift.list）在既有授权上下文内比较同一源资产的两个数据批次。批次、字段、主体键和比较范围在创建时固定；只读取双方授权且上下文允许的列，先投影未授权列再计算，未授权数据不会进入任何分布。主体键为空的行不进入比较，重复主体按主体整体做置换检验。

数值列报告缺失比例、经验分位和一阶 Wasserstein 距离；类别列报告含缺失类别的频率（高基数折叠到固定桶）和 Jensen–Shannon 距离；字段置换 p 值在同一分析族内做 Benjamini–Hochberg 校正，效应量与样本量同时保留。共同数值字段用仅以参照版本估计的均值和标准差标准化后计算能量距离，检验单列正常但相关结构改变的联合漂移。类型族变化、全空、常量、某侧无主体、两侧主体重叠、高基数等情形写入 boundaries 说明推断边界。

保存的诊断只含聚合结果，不含行级或未授权明细。每次读取或导出都重新校验授权、资产状态与批次摘要，撤权或来源失效会使读取标记失效并拒绝导出；旧分析不会因换版自动更新，新批次需要新分析。drift-demo 使用边际分布相同、相关结构不同的合成数据演示该路径。

也可执行下面的统一检查，按顺序进行语法编译、领域回归和完整本地演练，任一环节失败即退出。运行写入均在临时目录或内存数据库，重复执行不需清理已有业务账。正常数据规模的检查可在 90 秒内完成。

```sh
sh scripts/check.sh
```
