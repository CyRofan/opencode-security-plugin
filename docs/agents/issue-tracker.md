# 任务跟踪：本地 Markdown

本仓库的任务和规格以 Markdown 文件保存在 `.scratch/` 下。

## 文件约定

- 每个功能一个目录：`.scratch/<feature-slug>/`。
- 规格文件：`.scratch/<feature-slug>/spec.md`。
- 每个任务独立保存为 `issues/<NN>-<slug>.md`，从 `01` 编号。
- 不将所有任务合并到一个文件。
- 任务状态记录在文件顶部附近的 `Status:` 行。
- 评论和讨论追加到文件末尾的 `## Comments` 下。

## 技能操作

当技能要求“发布到任务跟踪器”时，在对应功能目录下创建文件。
当技能要求“获取相关任务”时，读取用户提供的路径或编号所对应的文件。

## Wayfinder 操作

- 地图：`.scratch/<effort>/map.md`，记录笔记、已有决策和待探索事项。
- 子任务：`.scratch/<effort>/issues/<NN>-<slug>.md`。
- 类型：使用 `Type:` 行，取值为 research、prototype、grilling 或 task。
- 状态：使用 `Status:` 行，取值为 open、claimed 或 resolved。
- 依赖：使用 `Blocked by: NN, NN`；所有依赖均 resolved 后才可开始。
- 选择任务：按编号查找第一个 open、无阻塞、未认领的任务。
- 认领：开始工作前将状态改为 claimed 并保存。
- 完成：在 `## Answer` 下追加结果，将状态改为 resolved，
  并在地图的决策记录中追加结果摘要和链接。
