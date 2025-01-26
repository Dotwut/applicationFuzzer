import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import pyautogui
import logging
import psutil
import time
import subprocess
from threading import Thread, Event
import os
import platform

class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)

        # Create a canvas and scrollbar
        self.canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)

        # Create the scrollable frame
        self.scrollable_frame = ttk.Frame(self.canvas)

        # Configure the canvas
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        # Create a window in the canvas for the frame
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        # Configure canvas to expand horizontally
        self.canvas.bind('<Configure>', self.resize_canvas)

        # Configure the scrollbar
        self.canvas.configure(yscrollcommand=scrollbar.set)

        # Pack the canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bind mouse wheel
        self.scrollable_frame.bind('<Enter>', self._bound_to_mousewheel)
        self.scrollable_frame.bind('<Leave>', self._unbound_to_mousewheel)

    def resize_canvas(self, event):
        # Resize the canvas window when the frame is resized
        self.canvas.itemconfig(self.canvas_frame, width=event.width)

    def _bound_to_mousewheel(self, event):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)   # Windows
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)     # Linux
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)     # Linux
        self.canvas.bind_all("<Up>", self._on_up_key)               # Keyboard
        self.canvas.bind_all("<Down>", self._on_down_key)           # Keyboard

    def _unbound_to_mousewheel(self, event):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")
        self.canvas.unbind_all("<Up>")
        self.canvas.unbind_all("<Down>")

    def _on_mousewheel(self, event):
        if event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(1, "units")

    def _on_up_key(self, event):
        self.canvas.yview_scroll(-1, "units")

    def _on_down_key(self, event):
        self.canvas.yview_scroll(1, "units")

class FuzzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Coalfire Application Fuzzer")

        # Create main scrollable frame
        self.main_frame = ScrollableFrame(root)
        self.main_frame.pack(fill="both", expand=True)

        # Initialize variables
        self.stop_event = Event()
        self.fuzzing_thread = None
        self.os_type = tk.StringVar(value="macos")
        self.app_launch_delay = tk.IntVar(value=5)
        self.action_delay = tk.DoubleVar(value=0.5)

        # Configure pyautogui for faster operation
        pyautogui.FAILSAFE = True
        pyautogui.PAUSE = 0.0  # Remove default pause between actions
        pyautogui.MINIMUM_DURATION = 0.0  # Remove minimum duration for mouse movements
        pyautogui.MINIMUM_SLEEP = 0.0  # Remove minimum sleep time

        self.setup_gui()

    def setup_gui(self):
        # OS Selection
        os_frame = ttk.LabelFrame(self.main_frame.scrollable_frame, text="Operating System", padding=10)
        os_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        ttk.Radiobutton(os_frame, text="macOS", variable=self.os_type,
                        value="macos").grid(row=0, column=0, padx=5)
        ttk.Radiobutton(os_frame, text="Windows", variable=self.os_type,
                        value="windows").grid(row=0, column=1, padx=5)
        ttk.Radiobutton(os_frame, text="Linux", variable=self.os_type,
                        value="linux").grid(row=0, column=2, padx=5)

        # Timing Controls Frame
        timing_frame = ttk.LabelFrame(self.main_frame.scrollable_frame, text="Timing Controls", padding=10)
        timing_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        # Application Launch Delay
        launch_delay_frame = ttk.Frame(timing_frame)
        launch_delay_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        ttk.Label(launch_delay_frame, text="Application Launch Delay (seconds):").grid(row=0, column=0, padx=5, sticky="w")
        launch_delay_slider = ttk.Scale(launch_delay_frame, from_=5, to=30, orient="horizontal",
                                        variable=self.app_launch_delay,
                                        command=self.update_launch_delay_text)
        launch_delay_slider.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.launch_delay_entry = ttk.Entry(launch_delay_frame, width=5)
        self.launch_delay_entry.grid(row=0, column=2, padx=5)
        self.launch_delay_entry.insert(0, str(self.app_launch_delay.get()))
        self.launch_delay_entry.bind('<Return>', self.update_launch_delay_slider)
        self.launch_delay_entry.bind('<FocusOut>', self.update_launch_delay_slider)

        # Action Execution Delay
        action_delay_frame = ttk.Frame(timing_frame)
        action_delay_frame.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        ttk.Label(action_delay_frame, text="Action Execution Delay (seconds):").grid(row=0, column=0, padx=5, sticky="w")
        action_delay_slider = ttk.Scale(action_delay_frame, from_=0.0, to=1.0, orient="horizontal",
                                        variable=self.action_delay,
                                        command=self.update_action_delay_text)
        action_delay_slider.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.action_delay_entry = ttk.Entry(action_delay_frame, width=5)
        self.action_delay_entry.grid(row=0, column=2, padx=5)
        self.action_delay_entry.insert(0, str(self.action_delay.get()))
        self.action_delay_entry.bind('<Return>', self.update_action_delay_slider)
        self.action_delay_entry.bind('<FocusOut>', self.update_action_delay_slider)

        # Help text
        help_text = "Launch Delay: Time to wait after application starts\nAction Delay: Time between each action in sequence"
        ttk.Label(timing_frame, text=help_text, justify="left").grid(row=2, column=0, columnspan=3, padx=5, pady=5)

        # Initial Setup Sequence Frame
        initial_setup_frame = ttk.LabelFrame(self.main_frame.scrollable_frame,
                                            text="Initial Setup Sequence (Executes Once)", padding=10)
        initial_setup_frame.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")

        # Initial sequence list with scrollbar
        initial_list_frame = ttk.Frame(initial_setup_frame)
        initial_list_frame.grid(row=0, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        self.initial_control_list = tk.Listbox(initial_list_frame, width=50, height=5)
        initial_scrollbar = ttk.Scrollbar(initial_list_frame, orient="vertical",
                                        command=self.initial_control_list.yview)
        self.initial_control_list.configure(yscrollcommand=initial_scrollbar.set)
        self.initial_control_list.grid(row=0, column=0, sticky="nsew")
        initial_scrollbar.grid(row=0, column=1, sticky="ns")

        # Action buttons for initial setup
        initial_action_frame = ttk.LabelFrame(initial_setup_frame, text="Add Initial Action", padding=5)
        initial_action_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        # Mouse Actions for initial setup
        initial_mouse_frame = ttk.LabelFrame(initial_action_frame, text="Mouse Actions", padding=5)
        initial_mouse_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        ttk.Button(initial_mouse_frame, text="Left Click",
                    command=lambda: self.add_initial_mouse_action("LEFT_CLICK")).grid(row=0, column=0, padx=2, pady=2)
        ttk.Button(initial_mouse_frame, text="Right Click",
                    command=lambda: self.add_initial_mouse_action("RIGHT_CLICK")).grid(row=0, column=1, padx=2, pady=2)

        # List manipulation buttons for initial setup
        initial_list_control_frame = ttk.Frame(initial_setup_frame)
        initial_list_control_frame.grid(row=2, column=0, columnspan=3, pady=5)

        ttk.Button(initial_list_control_frame, text="Remove Selected",
                    command=self.remove_initial_action).grid(row=0, column=0, padx=5)
        ttk.Button(initial_list_control_frame, text="Clear All",
                    command=self.clear_initial_actions).grid(row=0, column=1, padx=5)
        # Application Selection
        app_frame = ttk.LabelFrame(self.main_frame.scrollable_frame, text="Application Settings", padding=10)
        app_frame.grid(row=3, column=0, padx=5, pady=5, sticky="nsew")

        ttk.Label(app_frame, text="Application Path:").grid(row=0, column=0, sticky="w")
        self.app_path = tk.StringVar()
        ttk.Entry(app_frame, textvariable=self.app_path, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(app_frame, text="Browse", command=self.browse_app).grid(row=0, column=2)

        # Fuzzing List Selection
        ttk.Label(app_frame, text="Fuzz List:").grid(row=1, column=0, sticky="w")
        self.fuzz_list_path = tk.StringVar()
        ttk.Entry(app_frame, textvariable=self.fuzz_list_path, width=50).grid(row=1, column=1, padx=5)
        ttk.Button(app_frame, text="Browse", command=self.browse_fuzz_list).grid(row=1, column=2)

        # Log File Selection
        ttk.Label(app_frame, text="Log File:").grid(row=2, column=0, sticky="w")
        self.log_path = tk.StringVar(value="fuzz_crashes.txt")
        ttk.Entry(app_frame, textvariable=self.log_path, width=50).grid(row=2, column=1, padx=5)
        ttk.Button(app_frame, text="Browse", command=self.browse_log).grid(row=2, column=2)

        # Setup Control Frame
        self.setup_control_frame()

        # Status Label
        self.status_label = ttk.Label(self.main_frame.scrollable_frame, text="Status: Ready")
        self.status_label.grid(row=5, column=0, padx=5, pady=5, sticky="ew")

        # Control Buttons
        button_frame = ttk.Frame(self.main_frame.scrollable_frame, padding=10)
        button_frame.grid(row=6, column=0, padx=5, pady=5, sticky="ew")

        self.start_button = ttk.Button(button_frame, text="Start Fuzzing", command=self.start_fuzzing)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Fuzzing", command=self.stop_fuzzing, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=5)

    def update_launch_delay_text(self, value):
        """Update launch delay text box when slider moves"""
        self.launch_delay_entry.delete(0, tk.END)
        self.launch_delay_entry.insert(0, str(round(float(value))))

    def update_action_delay_text(self, value):
        """Update action delay text box when slider moves"""
        self.action_delay_entry.delete(0, tk.END)
        self.action_delay_entry.insert(0, str(round(float(value), 3)))

    def update_launch_delay_slider(self, event):
        """Update launch delay slider when text changes"""
        try:
            value = float(self.launch_delay_entry.get())
            if 5 <= value <= 30:
                self.app_launch_delay.set(value)
            else:
                self.launch_delay_entry.delete(0, tk.END)
                self.launch_delay_entry.insert(0, str(self.app_launch_delay.get()))
        except ValueError:
            self.launch_delay_entry.delete(0, tk.END)
            self.launch_delay_entry.insert(0, str(self.app_launch_delay.get()))

    def update_action_delay_slider(self, event):
        """Update action delay slider when text changes"""
        try:
            value = float(self.action_delay_entry.get())
            if 0 <= value <= 1:
                self.action_delay.set(value)
            else:
                self.action_delay_entry.delete(0, tk.END)
                self.action_delay_entry.insert(0, str(self.action_delay.get()))
        except ValueError:
            self.action_delay_entry.delete(0, tk.END)
            self.action_delay_entry.insert(0, str(self.action_delay.get()))

    def add_initial_mouse_action(self, action_type):
        """Add a mouse action to the initial setup sequence"""
        self.update_status("Select position for initial setup...")
        self.root.iconify()
        time.sleep(2)
        x, y = pyautogui.position()
        self.initial_control_list.insert(tk.END, f"{action_type},{x},{y}")
        self.root.deiconify()
        self.update_status("Ready")

    def remove_initial_action(self):
        """Remove selected action from initial setup sequence"""
        selection = self.initial_control_list.curselection()
        if selection:
            self.initial_control_list.delete(selection)

    def clear_initial_actions(self):
        """Clear all actions from initial setup sequence"""
        self.initial_control_list.delete(0, tk.END)

    def execute_initial_setup(self):
        """Execute the initial setup sequence once"""
        action_delay = float(self.action_delay.get())

        for i in range(self.initial_control_list.size()):
            if self.stop_event.is_set():
                return

            action = self.initial_control_list.get(i)
            self.update_status(f"Executing initial setup action: {action}")

            try:
                if "," in action:  # Mouse action with coordinates
                    parts = action.split(",")
                    action_type = parts[0]

                    if action_type == "LEFT_CLICK":
                        pyautogui.click(int(parts[1]), int(parts[2]), _pause=False)
                    elif action_type == "RIGHT_CLICK":
                        pyautogui.rightClick(int(parts[1]), int(parts[2]), _pause=False)

                    if action_delay > 0:
                        time.sleep(action_delay)

            except Exception as e:
                logging.error(f"Error executing initial setup action {action}: {str(e)}")
                self.update_status(f"Error in initial setup: {str(e)}")
    def setup_control_frame(self):
        # Control Sequence Frame
        control_frame = ttk.LabelFrame(self.main_frame.scrollable_frame, text="Main Control Sequence Builder", padding=10)
        control_frame.grid(row=4, column=0, padx=5, pady=5, sticky="nsew")

        # Control sequence list with scrollbar
        list_frame = ttk.Frame(control_frame)
        list_frame.grid(row=0, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        self.control_list = tk.Listbox(list_frame, width=50, height=10)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.control_list.yview)
        self.control_list.configure(yscrollcommand=scrollbar.set)
        self.control_list.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Action buttons frame
        action_frame = ttk.LabelFrame(control_frame, text="Add Action", padding=5)
        action_frame.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        # Mouse Actions
        mouse_frame = ttk.LabelFrame(action_frame, text="Mouse Actions", padding=5)
        mouse_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        ttk.Button(mouse_frame, text="Left Click",
                    command=lambda: self.add_mouse_action("LEFT_CLICK")).grid(row=0, column=0, padx=2, pady=2)
        ttk.Button(mouse_frame, text="Right Click",
                    command=lambda: self.add_mouse_action("RIGHT_CLICK")).grid(row=0, column=1, padx=2, pady=2)
        ttk.Button(mouse_frame, text="Double Click",
                    command=lambda: self.add_mouse_action("DOUBLE_CLICK")).grid(row=1, column=0, padx=2, pady=2)
        ttk.Button(mouse_frame, text="Click and Drag",
                    command=lambda: self.add_mouse_action("DRAG")).grid(row=1, column=1, padx=2, pady=2)

        # Keyboard Actions
        keyboard_frame = ttk.LabelFrame(action_frame, text="Keyboard Actions", padding=5)
        keyboard_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        ttk.Button(keyboard_frame, text="Press Enter",
                    command=lambda: self.add_keyboard_action("ENTER")).grid(row=0, column=0, padx=2, pady=2)
        ttk.Button(keyboard_frame, text="Ctrl+A (Select All)",
                    command=lambda: self.add_keyboard_action("CTRL_A")).grid(row=0, column=1, padx=2, pady=2)
        ttk.Button(keyboard_frame, text="Ctrl+V (Paste Fuzz Input)",
                    command=lambda: self.add_keyboard_action("CTRL_V")).grid(row=0, column=2, padx=2, pady=2)
        ttk.Button(keyboard_frame, text="Ctrl+C (Copy)",
                    command=lambda: self.add_keyboard_action("CTRL_C")).grid(row=1, column=0, padx=2, pady=2)
        ttk.Button(keyboard_frame, text="Tab",
                    command=lambda: self.add_keyboard_action("TAB")).grid(row=1, column=1, padx=2, pady=2)
        ttk.Button(keyboard_frame, text="Escape",
                    command=lambda: self.add_keyboard_action("ESC")).grid(row=1, column=2, padx=2, pady=2)

        # List manipulation buttons
        list_control_frame = ttk.Frame(control_frame)
        list_control_frame.grid(row=3, column=0, columnspan=3, pady=5)

        ttk.Button(list_control_frame, text="Remove Selected",
                    command=self.remove_selected_action).grid(row=0, column=0, padx=5)
        ttk.Button(list_control_frame, text="Clear All",
                    command=self.clear_actions).grid(row=0, column=1, padx=5)
        ttk.Button(list_control_frame, text="Move Up",
                    command=self.move_action_up).grid(row=0, column=2, padx=5)
        ttk.Button(list_control_frame, text="Move Down",
                    command=self.move_action_down).grid(row=0, column=3, padx=5)

    def setup_logging(self):
        """Configure logging with custom format"""
        log_file = self.log_path.get()
        if not log_file.endswith('.txt'):
            log_file = log_file.rsplit('.', 1)[0] + '.txt'
            self.log_path.set(log_file)

        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def log_fuzz_input(self, fuzz_input, status="TESTING"):
        """Log each fuzz input with timestamp"""
        logging.info(f"Fuzz Input: {fuzz_input} - Status: {status}")

    def update_status(self, message):
        """Update status label in a thread-safe way"""
        try:
            self.status_label.config(text=f"Status: {message}")
            self.root.update_idletasks()  # More efficient than full update
        except:
            pass  # Ignore any update errors
    def browse_app(self):
        os_type = self.os_type.get()

        if os_type == "macos":
            filetypes = [("Applications", "*.app"), ("All files", "*")]
            initialdir = "/Applications"
        elif os_type == "windows":
            filetypes = [("Executables", "*.exe"), ("All files", "*")]
            initialdir = os.environ.get("ProgramFiles", "C:\\Program Files")
        else:  # Linux
            filetypes = [("All files", "*")]
            # Check common Linux binary locations
            common_paths = [
                "/usr/bin",
                "/usr/local/bin",
                "/opt",
                os.path.expanduser("~"),  # Home directory
                os.path.expanduser("~/Desktop")
            ]
            # Use the first existing path as initial directory
            initialdir = next((path for path in common_paths if os.path.exists(path)), "/")

        filename = filedialog.askopenfilename(
            title="Select Application",
            initialdir=initialdir,
            filetypes=filetypes
        )

        if filename:
            self.app_path.set(filename)

    def browse_fuzz_list(self):
        filename = filedialog.askopenfilename(
            title="Select Fuzz List",
            filetypes=[("Text files", "*.txt"), ("All files", "*")]
        )
        if filename:
            self.fuzz_list_path.set(filename)

    def browse_log(self):
        filename = filedialog.asksaveasfilename(
            title="Select Log File",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*")]
        )
        if filename:
            self.log_path.set(filename)

    def add_mouse_action(self, action_type):
        self.update_status("Select position...")
        self.root.iconify()
        time.sleep(2)  # Wait for user to position mouse
        x, y = pyautogui.position()

        if action_type == "DRAG":
            self.root.deiconify()
            messagebox.showinfo("Select Second Position",
                                "Now select the end position for drag operation")
            self.root.iconify()
            time.sleep(2)
            x2, y2 = pyautogui.position()
            self.control_list.insert(tk.END, f"DRAG,{x},{y},{x2},{y2}")
        else:
            self.control_list.insert(tk.END, f"{action_type},{x},{y}")

        self.root.deiconify()
        self.update_status("Ready")

    def add_keyboard_action(self, action_type):
        self.control_list.insert(tk.END, action_type)

    def remove_selected_action(self):
        selection = self.control_list.curselection()
        if selection:
            self.control_list.delete(selection)

    def clear_actions(self):
        self.control_list.delete(0, tk.END)

    def move_action_up(self):
        selection = self.control_list.curselection()
        if selection and selection[0] > 0:
            text = self.control_list.get(selection[0])
            self.control_list.delete(selection[0])
            self.control_list.insert(selection[0]-1, text)
            self.control_list.selection_set(selection[0]-1)

    def move_action_down(self):
        selection = self.control_list.curselection()
        if selection and selection[0] < self.control_list.size()-1:
            text = self.control_list.get(selection[0])
            self.control_list.delete(selection[0])
            self.control_list.insert(selection[0]+1, text)
            self.control_list.selection_set(selection[0]+1)

    def launch_application(self, app_path):
        """Launch application based on OS type"""
        os_type = self.os_type.get()

        try:
            if os_type == "macos":
                if app_path.endswith('.app'):
                    process = subprocess.Popen(['open', app_path], shell=False)
                else:
                    process = subprocess.Popen([app_path], shell=False)
            elif os_type == "windows":
                process = subprocess.Popen([app_path], shell=True)
            else:  # Linux
                # Make sure the file is executable
                if not os.access(app_path, os.X_OK):
                    os.chmod(app_path, os.stat(app_path).st_mode | 0o111)

                # Handle different types of Linux executables
                if app_path.endswith('.AppImage'):
                    process = subprocess.Popen([app_path], shell=False)
                elif app_path.endswith('.sh'):
                    process = subprocess.Popen(['bash', app_path], shell=False)
                elif '/' in app_path:  # Full path provided
                    process = subprocess.Popen([app_path], shell=False)
                else:  # Command in PATH
                    process = subprocess.Popen([app_path], shell=False, env=os.environ.copy())

            return process

        except Exception as e:
            error_msg = f"Failed to launch application: {str(e)}"
            logging.error(error_msg)
            self.update_status(error_msg)
            messagebox.showerror("Error", error_msg)
            return None

    def verify_application_path(self, app_path):
        """Verify application path based on OS type"""
        os_type = self.os_type.get()

        if not os.path.exists(app_path):
            # For Linux, check if it's a command in PATH
            if os_type == "linux":
                from shutil import which
                if which(app_path):
                    return True, "Valid command in PATH"
            return False, "Application path does not exist"

        if os_type == "macos":
            if app_path.endswith('.app'):
                info_plist = os.path.join(app_path, 'Contents', 'Info.plist')
                if not os.path.exists(info_plist):
                    return False, "Invalid application bundle"
            elif not os.access(app_path, os.X_OK):
                return False, "Application is not executable"

        elif os_type == "windows":
            if not app_path.lower().endswith('.exe'):
                return False, "Not a valid Windows executable"

        else:  # Linux
            # Check if file is executable or can be made executable
            try:
                if not os.access(app_path, os.X_OK):
                    os.chmod(app_path, os.stat(app_path).st_mode | 0o111)
            except Exception as e:
                return False, f"Cannot make file executable: {str(e)}"

        return True, "Valid application path"

    def execute_control_sequence(self, fuzz_input):
        action_delay = float(self.action_delay.get())

        for i in range(self.control_list.size()):
            if self.stop_event.is_set():
                return

            action = self.control_list.get(i)

            try:
                if "," in action:  # Mouse action with coordinates
                    parts = action.split(",")
                    action_type = parts[0]

                    if action_type == "LEFT_CLICK":
                        pyautogui.click(int(parts[1]), int(parts[2]), _pause=False)
                    elif action_type == "RIGHT_CLICK":
                        pyautogui.rightClick(int(parts[1]), int(parts[2]), _pause=False)
                    elif action_type == "DOUBLE_CLICK":
                        pyautogui.doubleClick(int(parts[1]), int(parts[2]), _pause=False)
                    elif action_type == "DRAG":
                        pyautogui.moveTo(int(parts[1]), int(parts[2]), duration=0, _pause=False)
                        pyautogui.dragTo(int(parts[3]), int(parts[4]), duration=action_delay, _pause=False)
                else:  # Keyboard action
                    if action == "ENTER":
                        pyautogui.press('enter', _pause=False)
                    elif action == "CTRL_A":
                        pyautogui.hotkey('ctrl', 'a', _pause=False)
                    elif action == "CTRL_V":
                        pyautogui.write(fuzz_input, interval=0.0)
                    elif action == "CTRL_C":
                        pyautogui.hotkey('ctrl', 'c', _pause=False)
                    elif action == "TAB":
                        pyautogui.press('tab', _pause=False)
                    elif action == "ESC":
                        pyautogui.press('esc', _pause=False)

                if action_delay > 0:
                    time.sleep(action_delay)

            except Exception as e:
                logging.error(f"Error executing action {action}: {str(e)}")
                self.update_status(f"Error: {str(e)}")

    def start_fuzzing(self):
        if not all([self.app_path.get(), self.fuzz_list_path.get(), self.log_path.get()]):
            messagebox.showerror("Error", "Please fill in all required fields")
            return

        if self.control_list.size() == 0:
            messagebox.showerror("Error", "Please add at least one action to the sequence")
            return

        self.stop_event.clear()
        self.fuzzing_thread = Thread(target=self.fuzz_process)
        self.fuzzing_thread.start()

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

    def stop_fuzzing(self):
        self.stop_event.set()
        self.update_status("Stopping...")
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.update_status("Ready")

    def fuzz_process(self):
        try:
            self.setup_logging()
            app_path = self.app_path.get()

            # Verify application path
            is_valid, message = self.verify_application_path(app_path)
            if not is_valid:
                raise ValueError(message)

            self.update_status("Launching application...")
            process = self.launch_application(app_path)

            if not process:
                raise ValueError("Failed to launch application")

            # Use the user-defined launch delay
            launch_delay = int(self.app_launch_delay.get())
            self.update_status(f"Waiting {launch_delay} seconds for application to load...")
            time.sleep(launch_delay)

            # Execute initial setup sequence if any
            if self.initial_control_list.size() > 0:
                self.update_status("Executing initial setup sequence...")
                self.execute_initial_setup()
                logging.info("Initial setup sequence completed")

            self.update_status("Loading fuzz list...")
            try:
                with open(self.fuzz_list_path.get(), 'r', encoding='utf-8', errors='replace') as f:
                    inputs = [line.strip() for line in f.readlines()]
                    logging.info(f"Successfully loaded {len(inputs)} inputs using UTF-8 encoding")
            except UnicodeDecodeError:
                try:
                    with open(self.fuzz_list_path.get(), 'r', encoding='latin-1') as f:
                        inputs = [line.strip() for line in f.readlines()]
                        logging.info(f"Successfully loaded {len(inputs)} inputs using Latin-1 encoding")
                except Exception as e:
                    error_msg = f"Failed to load fuzz list with both UTF-8 and Latin-1 encodings: {str(e)}"
                    logging.error(error_msg)
                    raise ValueError(error_msg)

            total_inputs = len(inputs)
            update_interval = max(1, min(100, total_inputs // 100))  # Update every 1% or at least every input
            last_update_time = time.time()
            update_threshold = 0.1  # Minimum time between updates in seconds

            action_delay = float(self.action_delay.get())
            for idx, fuzz_input in enumerate(inputs, 1):
                if self.stop_event.is_set():
                    logging.info("Fuzzing stopped by user")
                    self.root.after(0, self.update_status, "Fuzzing stopped by user")
                    break

                # Update status less frequently for better performance
                current_time = time.time()
                if idx % update_interval == 0 or (current_time - last_update_time) >= update_threshold:
                    self.root.after(0, self.update_status,
                                    f"Testing input {idx}/{total_inputs} ({(idx/total_inputs)*100:.1f}%)")
                    last_update_time = current_time

                self.log_fuzz_input(fuzz_input)

                try:
                    self.execute_control_sequence(fuzz_input)
                except Exception as e:
                    logging.error(f"Error executing sequence for input {fuzz_input}: {str(e)}")
                    continue

                if not psutil.pid_exists(process.pid):
                    crash_msg = f"Crash detected with input: {fuzz_input}"
                    logging.error(crash_msg)
                    self.log_fuzz_input(fuzz_input, "CRASH DETECTED")
                    self.root.after(0, self.update_status, crash_msg)
                    break

                time.sleep(action_delay)

        except Exception as e:
            error_msg = f"Error during fuzzing: {str(e)}"
            logging.error(error_msg)
            self.root.after(0, self.update_status, error_msg)
            self.root.after(0, messagebox.showerror, "Error", error_msg)
        finally:
            try:
                if process and psutil.pid_exists(process.pid):
                    process.terminate()
                    logging.info("Target application terminated")
            except:
                pass
            self.root.after(0, self.update_status,
                            f"Fuzzing completed - Processed {total_inputs} inputs")
            self.root.after(0, self.stop_fuzzing)

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("800x800")  # Set initial window size
    app = FuzzerGUI(root)
    root.mainloop()
