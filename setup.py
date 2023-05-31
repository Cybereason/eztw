from setuptools import setup

# To build a wheel: python setup.py bdist_wheel

setup(
    name="eztw",    
    version="1.0.3",
    description="Easy Python wrapper for ETW",
    url="https://github.com/wild-strudel/eztw",
    author="Uri Sternfeld",
    packages=["eztw", "eztw.scripts"],
    python_requires=">=3.10, <4",
    install_requires=["pywin32"],
    license="MIT",
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: Implementation :: CPython',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: Microsoft :: Windows :: Windows 10',
    ],
)