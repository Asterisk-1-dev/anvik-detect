"""Export JSON Schema for RingScope Output model."""

import json
from pathlib import Path
from detection.models import Output


def export_schema(out_path: Path | str = "schema/output.schema.json") -> None:
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    schema = Output.model_json_schema()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2, ensure_ascii=False)
    print(f"JSON schema successfully exported to {path}")


if __name__ == "__main__":
    export_schema()
