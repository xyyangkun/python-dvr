# python-dvr
Python library for configuring a wide range of IP cameras which use the NETsurveillance ActiveX plugin

## DeviceManager.py
DeviceManager.py is standalone tkinter and console interface program souch as original DeviceManager.exe
it possible work on both systems - if no TK - it starts with console interface

## DVR-IP, NetSurveillance  or "Sofia" Protocol
The NETSurveillance ActiveX plugin uses a TCP based protocol refered to simply as the "Digital Video Recorder Interface Protocol" by the "Hangzhou male Mai Information Co".

There is very little software support or documentation other than through tools provided by the manufacturers these cameras, which leaves many configuration options inaccessible.

*Command and response codes can be found here:*

https://gist.github.com/ekwoodrich/a6d7b8db8f82adf107c3c366e61fd36f

## Usage

```python
from dvrip import DVRIPCam
from time import sleep
cam = DVRIPCam("192.168.1.10","admin","")
cam.login()
time = cam.get_time()
print "CAM Time:",time
#Reboot test
cam.reboot()
sleep(60) #Wait for CAM
cam.login()
#Sync CAM Time with PC Time
cam.set_time()
cam.close()
```
## Acknowledgements

*Telnet access creds from gabonator*

https://gist.github.com/gabonator/74cdd6ab4f733ff047356198c781f27d
