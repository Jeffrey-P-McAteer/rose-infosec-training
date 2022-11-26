
# Helper functions to ensure 3rd-party code is available for
# other tools to use

import traceback
import subprocess
import sys
import readline
import shelve

# If module_name is installed, load it, else
# try to install package_name and then try loading module_name again.
def importinate(module_name, package_name=None):
  if package_name is None:
    package_name = module_name

  try:
    return __import__(module_name)
  except:
    traceback.print_exc()
    subprocess.run([
      sys.executable, *(f'-m pip install --user {package_name}'.split())
    ])
    return __import__(module_name)


def input_with_prefill(prompt, text):
    def hook():
        readline.insert_text(text)
        readline.redisplay()
    readline.set_pre_input_hook(hook)
    result = input(prompt)
    readline.set_pre_input_hook()
    return result

def cmd(*parts, check=True):
  if len(parts) == 1 and isinstance(parts[0], list):
    parts = parts[0]
  print(f'CMD> {" ".join(list(parts))}')
  subprocess.run(list(parts), check=check)

# Silences errors, useful for parsing unknown data
def maybe(function):
  try:
    return function()
  except:
    return None


def with_memory(callback, memory_shelve_file_path='memory.shelve'):
  ret = None
  with shelve.open(memory_shelve_file_path) as db:
    ret = callback(db)
  return ret



