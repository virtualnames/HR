import subprocess
import os

def run_test_script(script_name):
    script_path = os.path.join(os.path.dirname(__file__), script_name)
    if os.path.exists(script_path):
        print(f"Executing {script_name}...")
        try:
            result = subprocess.run(["bash", script_path], capture_output=True, text=True, check=True)
            print(result.stdout)
            if result.stderr:
                print("Error Output:")
                print(result.stderr)
            print(f"{script_name} execution completed.")
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while executing {script_name}:")
            print(e.stderr)
    else:
        print(f"Error: Script not found - {script_path}")

    input("Press Enter to continue...")


def main():
    while True:
        choice = input("Select test level to execute (1: BasicLayer, 2: ExtensionLayer, 3: EncodingLayer, q: Quit): ").lower()

        if choice == '1':
            run_test_script("Tester/Tester_basic.sh")
        elif choice == '2':
            run_test_script("Tester/Tester_extended.sh")
        elif choice == '3':
            run_test_script("Tester/Tester_physical.sh")
        elif choice == 'q':
           print("Exiting program")
            break
        else:
           print("Invalid selection, please try again")


if __name__ == "__main__":
    main()