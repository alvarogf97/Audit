# Audit Server

The number of malware increases 
every day as fast as the number 
of vulnerabilities which can be 
exploited with malicious purpose. 
It is important that users know the 
level of commitment of their devices 
in order to allow them acting against 
those risks by neutralizing or decreasing 
their effects as much as possible.

The goal of the study is to provide 
users a tool which can inform them of 
the possible risks their devices could be 
exposed to, automating the exploit of well 
known vulnerabilities in a controlled way 
as well as detecting them in real time, 
allowing users to kill with processes which 
could be the origin of the risk. Moreover, 
this tool could sniff network packets in order 
to detect anomalies in the network traffic.

In conclusion, cyber-security will be more 
important due to the necessity of protecting 
the privacy and integrity of users in a world 
which every day is more interconnected and 
technological.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

You need to have python 3.5+ in order to use this application and pip installed on your computer.

#### Linux

You need to install some libs before installation:

```
python-dev (for your version of python)
gtk (preferably version 3, but depends on your needs)
gstreamer
gstreamer-plugins-base
glut
libwebkitgtk (matching your gtk version)
libjpeg
libpng
libtiff
libsdl
libnotify
libsm
libpcap-dev
```

You can install them by executting the next commands:

##### Ubuntu/Debian based distros:

```
sudo apt install make gcc libgtk-3-dev libwebkitgtk-dev libwebkitgtk-3.0-dev libgstreamer-gl1.0-0 freeglut3 freeglut3-dev python-gst-1.0 python3-gst-1.0 libglib2.0-dev ubuntu-restricted-extras libgstreamer-plugins-base1.0-dev libpcap-dev
```

##### RHEL based distros:

```
Give examples
```

##### Arch based distros:

```
Give examples
```

##### Install WxPython:

You can compile and install it by yourself:

```
pip install -U pip
pip install -U six wheel setuptools
pip download wxPython
pip wheel -v wxPython-4.0.4.tar.gz  2>&1 | tee build.log
```

Or install it using pip:

```
pip install wxpython
```

Or just install by the compiled wheel in https://mega.nz/#!B4BwBIiZ!5Hvl2vkVfeRwYPcRIDVGgNedjma7e3jd1ck8GClmc9g using easy_install:

````angular2
easy_install wxPython-4.0.4-cp36-cp36m-linux_x86_64.whl
````
#### Windows

You can install PCAP lib by yourself with this link 
https://nmap.org/npcap/dist/npcap-0.99-r7.exe or let Audit install it for you.

#### Mac OS

Dependencies:

```
Give examples
```

### Installing

Cloning this repository on a folder in your computer:

```
git clone https://github.com/alvarogf97/Audit
```

Go to cloning directory and execute:

```
pip install -r requirements.txt
```

finally execute:

```
python start.py
```

## Build with

You can use pyinstaller in order to get an executable from this application.
Please let's go to builder folder and execute the script depending on your
operative system. 

- Install pyinstaller
````pip install pyinstaller````
- Execute your os script in builder folder

## Authors

* **Álvaro García**

See also a [mobile client](https://github.com/alvarogf97/Client_Audit) for this application.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

