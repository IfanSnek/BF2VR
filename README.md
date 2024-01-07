# BF2VR
[![](https://img.shields.io/badge/Discord-Testers%20-blueviolet)](https://discord.gg/mrKYwzd3N4)
### This is a full VR mod for Star Wars: Battlefront II (2017)
#### Note this is a work-in-progress
_This is the beta version. The alpha version is archived at [IfanSnek/BF2VR-Alpha](https://github.com/IfanSnek/BF2VR-Alpha/)_

## Installation
Download the ZIP file from the releases page **when it's available.**

Extract to a folder, then whitelist that folder in Windows Defender/Antivirus.

*That's all :)*

## Usage
1) Launch Battlefront II and wait for at least the menu to load. See mandatory settings below.

2) Enter an **Arcade** match. No starfighters (yet).

3) Open your OpenXR runtime (Oculus grid area, SteamVR mountains, Virtual Desktop just neads to have VDXR enabled)

4) Double click `Loader.exe`. The VR will show the game now, see the controls section.

5) (Optional) Use the delete key to eject. This will crash the game sometimes but it's worth it if you would need to close the game for some reason anyway.

### Mandatory settings:
* DirectX 12 - Off
* TAA - High (it's disabled anyway but it must be on high)
* Window mode - borderless

### Controls
*Assumes the equivalent for an Oculus Touch controller.*

**Left thumb:** Walk

**A:** Jump

**B:** Dodge

**X:** Reload

**Y:** They call it "basic weapon"

*A/B/X/Y buttons are the same as the normal Xbox controls.*

**Left trigger:** Sprint

**Right trigger:** Fire

**Left Grip:** Left ability

**Right Grip:** Right ability

**Left and right grip:** Middle ability

> [!WARNING]  
> Do not play online. You will likely be banned. And unlike Palpatine, you're not allowed back. You can use [Kyber](https://github.com/ArmchairDevelopers/Kyber) servers though.

## Issues

Upload the `BF2VR.txt` file in `Documents/BF2VR` when you open an issue. If applicable, upload the minidump as well. Please check if an issue exists beforehand, and it would be great if you checked discord as well.

## Contributing

Pull requests are very welcome. Please use Google's C++ style guide. You can download [cpplint](https://pypi.org/project/cpplint/) and run the following in the /src/ directory:
` cpplint --linelength 1000 --recursive .`

## License
BF2VR is licensed under the GPL-3.0 license (see LICENSE file).

## Legal
Star Wars: Battlefront II is trademarked by Electronic Arts, which in not affiliated with this project. 

BF2VR is protected by [17 U.S. Code § 1201](https://www.law.cornell.edu/uscode/text/17/1201), which allows reverse engineering of programs for the sole use of interoperability. BF2VR allows Battlefront II with various OpenXR runtimes through the [OpenXR Specification](https://registry.khronos.org/OpenXR/specs/1.0/html/xrspec.html).

> The information acquired through the acts permitted under paragraph (1), and the means permitted under paragraph (2), may be made available to others if the person referred to in paragraph (1) or (2), as the case may be, provides such information or means solely for the purpose of enabling interoperability of an independently created computer program with other programs, and to the extent that doing so does not constitute infringement under this title or violate applicable law other than this section.
