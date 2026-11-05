import os
import zipfile

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    name = 'project-1.0.dist-info'
    os.mkdir(os.path.join(metadata_directory, name))
    with open(os.path.join(metadata_directory, name, 'METADATA'), 'w') as f:
        f.write('Metadata-Version: 2.1\nName: project\nVersion: 1.0\n')
    return name

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name = 'project-1.0-py3-none-any.whl'
    with zipfile.ZipFile(os.path.join(wheel_directory, name), 'w') as z:
        z.writestr('project-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: project\nVersion: 1.0\n')
        z.writestr('project-1.0.dist-info/WHEEL', 'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
        z.writestr('project-1.0.dist-info/RECORD', '')
    return name
