from setuptools import setup


__author__ = 'bs@bebop.co (Bo Shi)'


setup(
    name='iam_acctmgr',
    author='Bo Shi',
    author_email='bs@demeterr.com',
    version='0.1',
    py_modules=['iam_acctmgr'],
    install_requires=['botocore'],
    entry_points={
        'console_scripts': [
            'iam_acctmgr = iam_acctmgr:service',
            'iam_acctmgr_keys = iam_acctmgr:authorized_keys_command',
            'iam_acctmgr_configure = iam_acctmgr:configure_system',
        ],
    },

    license='Apache Software License',
    long_description=(
        'iam_acctmgr is a utility that integrates a Linux host'
        '  with Amazon Web Services IAM.'
    ),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Topic :: System',
    ],
)
