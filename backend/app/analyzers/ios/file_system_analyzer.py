import os
from pathlib import Path
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext

class FileSystemAnalyzer(BaseAnalyzer):
    name = "filesystem"

    def run(self, ctx: AnalyzerContext):
        def build_tree(path):
            tree = []
            try:
                for item in sorted(os.listdir(path)):
                    if item.startswith('.') or item == '__pycache__':
                        continue
                    full_path = os.path.join(path, item)
                    rel_path = os.path.relpath(full_path, ctx.app_root)
                    if os.path.isdir(full_path):
                        tree.append({
                            "name": item,
                            "type": "folder",
                            "path": rel_path,
                            "children": build_tree(full_path)
                        })
                    else:
                        size = os.path.getsize(full_path)
                        tree.append({
                            "name": item,
                            "type": "file",
                            "path": rel_path,
                            "size": size
                        })
            except Exception:
                pass
            return tree

        self.result = {"tree": build_tree(ctx.app_root)}
        return []
