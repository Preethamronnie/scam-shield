"""The sandboxed inspector process (started by sandbox.run_isolated).

Reads a file's bytes from stdin, inspects it with inspectors.py, and writes
the findings as JSON to stdout. Never executes anything from the file.
"""
import json
import sys


def main() -> None:
    kind = sys.argv[1]
    data = sys.stdin.buffer.read()
    try:
        from scamshield import inspectors
        if kind == "html":
            out = {"status": "ok", "value": inspectors.inspect_html(data, sys.argv[2] if len(sys.argv) > 2 else "")}
        else:
            func = {"pdf": inspectors.inspect_pdf, "apk": inspectors.inspect_apk, "email": inspectors.inspect_email}[kind]
            out = {"status": "ok", "value": func(data)}
    except inspectors.InspectError as e:
        out = {"status": "error", "error": str(e)}
    except MemoryError:
        out = {"status": "error", "error": "The file needed too much memory to inspect safely."}
    except Exception as e:
        out = {"status": "error", "error": f"The file couldn't be read ({type(e).__name__})."}
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
