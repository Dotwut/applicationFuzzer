# Application Fuzzer

A cross-platform GUI application fuzzer designed for automated testing of desktop applications. This tool allows for precise control over mouse and keyboard inputs, making it ideal for security testing and automated UI interaction testing.

## Features

- Cross-platform support (macOS, Windows, Linux)
- Graphical user interface for easy configuration
- Custom timing controls for application launch and action execution
- Initial setup sequence for application preparation
- Main fuzzing sequence for repeated testing
- Support for various input types (mouse clicks, keyboard shortcuts, text input)
- Detailed logging of all actions and crashes
- UTF-8 and Latin-1 encoding support for fuzz lists

## Installation

### Prerequisites

- Python 3.8 or higher
- Git (for cloning the repository)
- Operating system-specific dependencies (detailed below)

### Setting up the Development Environment

#### macOS

```
Clone the repository
git clone git@github.com:Dotwut/applicationFuzzer.git
cd application-fuzzer
Create and activate virtual environment
python3 -m venv venv
 source venv/bin/activate
Install dependencies
pip install -r requirements.txt
```

#### Linux (Ubuntu/Debian)

```
Install system dependencies
sudo apt-get update sudo apt-get install python3-tk scrot xclip
Clone the repository
git clone git@github.com:Dotwut/applicationFuzzer.git
Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate
Install dependencies
pip install -r requirements.txt
```

#### Windows

```
Clone the repository
git clone git@github.com:Dotwut/applicationFuzzer.git
cd application-fuzzer
Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate
Install dependencies
pip install -r requirements.txt
```

## Usage

1. Launch the application:
python3 desktopAppFuzzer.py


2. Configure the Application:
   - Select your operating system
   - Set timing controls for application launch and action delays
   - Browse and select your target application
   - Choose or create a fuzz list file (text file with test inputs)
   - Specify a log file location

3. Set Up Initial Sequence (Optional):
   - Add initial actions that will execute once after application launch
   - Use mouse clicks to set up the application state

4. Create Main Fuzzing Sequence:
   - Add mouse actions (Left Click, Right Click, Double Click, Drag)
   - Add keyboard actions (Enter, Ctrl+A, Ctrl+V for fuzz input, etc.)
   - Arrange actions in the desired order

5. Start Fuzzing:
   - Click "Start Fuzzing" to begin the automated testing
   - Monitor the status in the application window
   - Check the log file for detailed results

