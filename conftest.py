"""把仓库根目录加入 sys.path，保证 engine 嵌套包可被 pytest 导入。"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))