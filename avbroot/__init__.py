import os
import sys

external_dir = os.path.join(os.path.realpath(os.path.dirname(__file__)),
                            '..', 'external')

# OTA utilities (loaded first because there are multiple common.py files and
# this is the one we need to import)
sys.path.append(os.path.join(external_dir, 'build', 'tools', 'releasetools'))
# avbtool
sys.path.append(os.path.join(external_dir, 'avb'))
# Payload protobuf
sys.path.append(os.path.join(external_dir, 'update_engine', 'scripts'))
