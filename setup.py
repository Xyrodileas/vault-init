from setuptools import setup, find_packages
import os.path

def load_long_description():
    dir_name = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(dir_name, "README.md"), "r") as fh:
        long_description = fh.read()
    return long_description

setup(
    name='vault_init',
    version='1.0',
    description='Wrapper to init and unseal Hashicorp vault',
    long_description=load_long_description(),
    long_description_content_type="text/markdown",
    author='Jean-Yves NOLEN',
    author_email='jynolen+dev@gmail.com',
    url='https://github.com/jynolen/vault_init',
    keywords=['hashicorp', 'vault'],
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
    ],
    packages=find_packages(exclude=['docs*', 'tests*']),
    install_requires=[
        'hvac>=0.10.5',
        'gpg>=1.10.0',
    ],
    include_package_data=True,
    package_data={'vault_init': ['version']}
)
