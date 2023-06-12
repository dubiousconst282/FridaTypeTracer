import json
import frida
import sys
from pathlib import Path

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(target_process, output_dir):
    session = frida.attach(target_process)

    Path(output_dir).mkdir(exist_ok=False)

    script_args = {
        "work_dir": str(Path(__file__).parent),
        "output_dir": str(Path(output_dir).absolute()),
    }
    script_src = Path(__file__).with_name("agent.js").read_text()
    script_src = "const args = " + json.dumps(script_args) + ";\n\n" + script_src

    script = session.create_script(script_src)
    script.on('message', on_message)
    script.load()
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: %s <process name or PID> <output event dir>" % __file__)
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]

    main(target_process, sys.argv[2])