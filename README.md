# configuration-backup
A simple Python script to automatically backup Palo Alto Networks NGFW and Panorama configurations

This script requires Python 3 and the [Requests](http://docs.python-requests.org/en/master/) library to be installed to function correctly.

Two command line arguments are required with an optional argument:

```
-c / --config  - Path to the configuration .ini file (required)
-l / --log     - Path to the .log file (required)
-v / --verbose - Enable verbose logging output to the console, log file and Syslog (optional)
```

Help is also accessible by running the script with -h or --help.

```
$ python3 configuration-backup.py --help
usage: configuration-backup.py [-h] -c CONFIG -l LOG [-v]

Palo Alto Networks Automated Configuration Backup (Version: 1.0.0)

optional arguments:
  -h, --help                 show this help message and exit
  -c CONFIG, --config CONFIG Define the configuration file
  -l LOG, --log LOG          Define the log file
  -v, --verbose              Enable verbose logging output to the console and log file
```

Example without verbose logging:
```
$ python3 configuration-backup.py --config default-config.ini --log /var/log/configuration-backup/default.log
```

Example with verbose logging:
```
$ python3 configuration-backup.py --config default-config.ini --log /var/log/configuration-backup/default.log --verbose
```

All configuration is held within the .ini file
