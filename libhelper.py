
# Helper functions to ensure 3rd-party code is available for
# other tools to use

import traceback
import subprocess
import sys

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



