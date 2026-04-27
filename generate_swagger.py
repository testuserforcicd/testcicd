#!/usr/bin/env python3
"""
Генератор swagger.yaml для WAF API.

Запускать из директории WAF/:
    cd WAF && python generate_swagger.py

Файл swagger.yaml создаётся в WAF/swagger.yaml.
Swagger UI доступен по адресу /api/docs/ после запуска сервера.
"""
import os
import sys
import django

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "waf_project.settings")
django.setup()

from drf_spectacular.generators import SchemaGenerator
import yaml

generator = SchemaGenerator(title="WAF API", version="1.0.0")
schema = generator.get_schema(request=None, public=True)

output_path = os.path.join(BASE_DIR, "swagger.yaml")
with open(output_path, "w", encoding="utf-8") as f:
    yaml.dump(schema, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

paths = schema.get("paths", {})
print(f"[OK] swagger.yaml: {output_path}")
print(f"     Size: {os.path.getsize(output_path):,} bytes | Endpoints: {len(paths)}")
for path in sorted(paths):
    methods = [m.upper() for m in paths[path].keys()]
    print(f"     {'  '.join(methods):30s}  {path}")
print()
print("Swagger UI: http://localhost:8000/api/docs/")
print("ReDoc:      http://localhost:8000/api/redoc/")
