import itertools
import threading
import time
import sys

spinner_running = False

# Loading Spinner Function
def spinner(msg):
    for char in itertools.cycle(['|', '/', '-', '\\']):
        if not spinner_running:
            break
        sys.stdout.write(f'\r{msg} {char}')
        sys.stdout.flush()
        time.sleep(0.1)

# Start the spinner in a separate thread
def start_spinner(msg):
    global spinner_running
    spinner_running = True
    t = threading.Thread(target=spinner, args=(msg,))
    t.start()
    return t

# Stop the spinner
def stop_spinner(t):
    global spinner_running
    spinner_running = False
    t.join()
    sys.stdout.write('\r' + ' ' * 40 + '\r')  # Clear the spinner line
