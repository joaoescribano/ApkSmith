from setuptools import setup, find_packages

setup(
    name='apksmith',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[],
    author='João Escribano',
    author_email='joao.escribano@gmail.com',
    description='A library to download, modify and rebuild apks for network manipulation',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/joaoescribano/ApkSmith',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'apksmith=apksmith.cli:main',
        ],
    },
)