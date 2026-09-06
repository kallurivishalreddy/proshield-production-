@echo off
setlocal
set PYTHONIOENCODING=utf-8
set RC=0

echo === sources.html ===
python scripts\repro_one_page.py /static/sources.html source.list
if errorlevel 1 set RC=1

echo === cases.html ===
python scripts\repro_one_page.py /static/cases.html case.list
if errorlevel 1 set RC=1

echo === case.html (no id) ===
python scripts\repro_one_page.py /static/case.html
if errorlevel 1 set RC=1

echo === rules.html ===
python scripts\repro_one_page.py /static/rules.html rule.list
if errorlevel 1 set RC=1

echo === detections.html ===
python scripts\repro_one_page.py /static/detections.html detection.list rule.list
if errorlevel 1 set RC=1

echo === correlations.html ===
python scripts\repro_one_page.py /static/correlations.html correlation.list rule.list
if errorlevel 1 set RC=1

echo === timeline.html ===
python scripts\repro_one_page.py /static/timeline.html case.list
if errorlevel 1 set RC=1

echo === index.html ===
python scripts\repro_one_page.py /static/index.html overview.summary source.list rule.list case.list detection.list
if errorlevel 1 set RC=1

echo === health.html ===
python scripts\repro_one_page.py /static/health.html
if errorlevel 1 set RC=1

echo.
echo FINAL RC=%RC%
exit /b %RC%
