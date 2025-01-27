import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import pyautogui
import logging
import psutil
import time
import subprocess
import json
import os
import platform
import datetime
import base64
import re
from threading import Thread, Event
from pathlib import Path
import plotly.graph_objects as go
import plotly.express as px
from jinja2 import Template
import pandas as pd
import rstr
import shutil
from PIL import Image, ImageDraw, ImageFont
import threading
import platform
import webbrowser
from pathlib import Path
import signal

class FuzzerConfig:
    """Configuration management for the fuzzer"""
    def __init__(self):
        self.config = {
            'timeout': 30,
            'max_crashes': 100,
            'screenshot_on_crash': True,
            'save_sequence': True,
            'memory_threshold': 90,
            'cpu_threshold': 95,
            'report_dir': 'fuzzing_reports',
            'crashes_dir': 'crashes',
            'sequences_dir': 'sequences'
        }
        self.initialize_directories()

    def initialize_directories(self):
        """Create necessary directories if they don't exist"""
        for dir_name in ['report_dir', 'crashes_dir', 'sequences_dir']:
            Path(self.config[dir_name]).mkdir(parents=True, exist_ok=True)

    def load_config(self, file_path):
        """Load configuration from JSON file"""
        try:
            with open(file_path, 'r') as f:
                self.config.update(json.load(f))
        except Exception as e:
            logging.error(f"Error loading config: {str(e)}")

    def save_config(self, file_path):
        """Save current configuration to JSON file"""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {str(e)}")

class FuzzingStats:
    """Track and manage fuzzing statistics"""
    def __init__(self):
        self.total_inputs = 0
        self.crashes = 0
        self.start_time = None
        self.end_time = None
        self.crashes_by_type = {}
        self.events = []
        self.memory_usage = []
        self.cpu_usage = []
        self.crash_details = []

    def start_session(self):
        """Start a new fuzzing session"""
        self.start_time = datetime.datetime.now()
        self.events.append({
            'time': self.start_time,
            'type': 'session_start',
            'description': 'Fuzzing session started'
        })

    def end_session(self):
        """End the current fuzzing session"""
        self.end_time = datetime.datetime.now()
        self.events.append({
            'time': self.end_time,
            'type': 'session_end',
            'description': 'Fuzzing session ended'
        })

    def add_crash(self, crash_type, details):
        """Record a crash event"""
        self.crashes += 1
        self.crashes_by_type[crash_type] = self.crashes_by_type.get(crash_type, 0) + 1
        self.crash_details.append({
            'time': datetime.datetime.now(),
            'type': crash_type,
            'details': details
        })

    def add_resource_usage(self, cpu_percent, memory_percent):
        """Record resource usage"""
        timestamp = datetime.datetime.now()
        self.cpu_usage.append((timestamp, cpu_percent))
        self.memory_usage.append((timestamp, memory_percent))

    def generate_report_data(self):
        """Generate comprehensive report data"""
        duration = (self.end_time - self.start_time) if self.end_time else (datetime.datetime.now() - self.start_time)

        return {
            'summary': {
                'duration': str(duration),
                'total_inputs': self.total_inputs,
                'crashes': self.crashes,
                'crash_rate': (self.crashes / self.total_inputs * 100) if self.total_inputs > 0 else 0,
                'crashes_by_type': self.crashes_by_type
            },
            'timeline': {
                'events': self.events,
                'cpu_usage': self.cpu_usage,
                'memory_usage': self.memory_usage
            },
            'crashes': self.crash_details
        }

class ReportGenerator:
    """Generate detailed HTML reports for fuzzing sessions"""
    def __init__(self, stats, config):
        self.stats = stats
        self.config = config
        self.report_path = None

    def create_charts(self):
        """Create interactive charts using plotly"""
        # CPU Usage Chart
        cpu_df = pd.DataFrame(self.stats.cpu_usage, columns=['time', 'usage'])
        cpu_fig = px.line(cpu_df, x='time', y='usage', title='CPU Usage Over Time')
        cpu_chart = cpu_fig.to_html(full_html=False)

        # Memory Usage Chart
        mem_df = pd.DataFrame(self.stats.memory_usage, columns=['time', 'usage'])
        mem_fig = px.line(mem_df, x='time', y='usage', title='Memory Usage Over Time')
        mem_chart = mem_fig.to_html(full_html=False)

        # Crash Distribution Pie Chart
        crash_df = pd.DataFrame.from_dict(self.stats.crashes_by_type,
                                        orient='index', columns=['count'])
        crash_fig = px.pie(crash_df, values='count', names=crash_df.index,
                          title='Crash Distribution by Type')
        crash_chart = crash_fig.to_html(full_html=False)

        return {
            'cpu_chart': cpu_chart,
            'memory_chart': mem_chart,
            'crash_chart': crash_chart
        }
    def generate_html_report(self):
        """Generate a comprehensive HTML report"""
        report_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Application Fuzzer Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        .report-header {
            background-color: #f8f9fa;
            padding: 2rem;
            margin-bottom: 2rem;
            border-bottom: 2px solid #dee2e6;
        }
        .stats-card {
            margin-bottom: 1.5rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
        }
        .chart-container {
            margin-bottom: 2rem;
            padding: 1rem;
            border: 1px solid #dee2e6;
            border-radius: 0.25rem;
        }
        .crash-detail {
            margin-bottom: 1rem;
            padding: 1rem;
            background-color: #f8f9fa;
            border-left: 4px solid #dc3545;
        }
        .timeline-event {
            padding: 0.5rem;
            margin-bottom: 0.5rem;
            border-left: 3px solid #0d6efd;
        }
    </style>
</head>
<body>
    <div class="report-header">
        <div class="container">
            <h1 class="display-4">Application Fuzzing Report</h1>
            <p class="lead">Generated on {{ timestamp }}</p>
        </div>
    </div>

    <div class="container">
        <!-- Executive Summary -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card stats-card">
                    <div class="card-header">
                        <h2>Executive Summary</h2>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3">
                                <h5>Duration</h5>
                                <p>{{ summary.duration }}</p>
                            </div>
                            <div class="col-md-3">
                                <h5>Total Inputs</h5>
                                <p>{{ summary.total_inputs }}</p>
                            </div>
                            <div class="col-md-3">
                                <h5>Total Crashes</h5>
                                <p>{{ summary.crashes }}</p>
                            </div>
                            <div class="col-md-3">
                                <h5>Crash Rate</h5>
                                <p>{{ "%.2f"|format(summary.crash_rate) }}%</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="row mb-4">
            <div class="col-12">
                <h2>Performance Analysis</h2>
                <div class="chart-container">
                    {{ charts.cpu_chart|safe }}
                </div>
                <div class="chart-container">
                    {{ charts.memory_chart|safe }}
                </div>
                <div class="chart-container">
                    {{ charts.crash_chart|safe }}
                </div>
            </div>
        </div>

        <!-- Crash Details -->
        <div class="row mb-4">
            <div class="col-12">
                <h2>Crash Details</h2>
                {% for crash in crashes %}
                <div class="crash-detail">
                    <h5>{{ crash.type }}</h5>
                    <p><strong>Time:</strong> {{ crash.time }}</p>
                    <p><strong>Details:</strong> {{ crash.details }}</p>
                    {% if crash.screenshot %}
                    <img src="data:image/png;base64,{{ crash.screenshot }}"
                            class="img-fluid" alt="Crash Screenshot">
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- Timeline -->
        <div class="row mb-4">
            <div class="col-12">
                <h2>Event Timeline</h2>
                {% for event in timeline.events %}
                <div class="timeline-event">
                    <p><strong>{{ event.time }}</strong></p>
                    <p>{{ event.description }}</p>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""
        # Generate charts
        charts = self.create_charts()

        # Prepare template data
        template_data = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': self.stats.generate_report_data()['summary'],
            'charts': charts,
            'crashes': self.stats.crash_details,
            'timeline': {
                'events': self.stats.events
            }
        }

        # Render template
        template = Template(report_template)
        report_html = template.render(**template_data)

        # Save report
        report_filename = f"fuzzing_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = os.path.join(self.config.config['report_dir'], report_filename)

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_html)

        self.report_path = report_path
        return report_path

    def export_data(self, format='json'):
        """Export fuzzing data in various formats"""
        data = self.stats.generate_report_data()
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

        if format == 'json':
            filename = f"fuzzing_data_{timestamp}.json"
            with open(os.path.join(self.config.config['report_dir'], filename), 'w') as f:
                json.dump(data, f, indent=4, default=str)
        elif format == 'csv':
            # Export crash data
            crash_df = pd.DataFrame(data['crashes'])
            crash_df.to_csv(os.path.join(self.config.config['report_dir'],
                                        f"crashes_{timestamp}.csv"), index=False)

            # Export resource usage data
            cpu_df = pd.DataFrame(self.stats.cpu_usage, columns=['time', 'usage'])
            cpu_df.to_csv(os.path.join(self.config.config['report_dir'],
                                        f"cpu_usage_{timestamp}.csv"), index=False)

            mem_df = pd.DataFrame(self.stats.memory_usage, columns=['time', 'usage'])
            mem_df.to_csv(os.path.join(self.config.config['report_dir'],
                                        f"memory_usage_{timestamp}.csv"), index=False)

class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)

        # Create a canvas and scrollbar
        self.canvas = tk.Canvas(self)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)

        # Create the scrollable frame
        self.scrollable_frame = ttk.Frame(self.canvas)
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        # Create a window in the canvas for the frame
        self.canvas_frame = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        # Configure canvas to expand horizontally
        self.canvas.bind('<Configure>', self.resize_canvas)

        # Configure the scrollbar
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Pack the canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Bind mouse wheel
        self.scrollable_frame.bind('<Enter>', self._bound_to_mousewheel)
        self.scrollable_frame.bind('<Leave>', self._unbound_to_mousewheel)

        # Bind keyboard navigation
        self.scrollable_frame.bind('<Up>', self._on_up_key)
        self.scrollable_frame.bind('<Down>', self._on_down_key)
        self.scrollable_frame.bind('<Prior>', self._on_page_up)
        self.scrollable_frame.bind('<Next>', self._on_page_down)

    def resize_canvas(self, event):
        # Resize the canvas window when the frame is resized
        self.canvas.itemconfig(self.canvas_frame, width=event.width)

    def _bound_to_mousewheel(self, event):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)

    def _unbound_to_mousewheel(self, event):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _on_mousewheel(self, event):
        if event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(1, "units")

    def _on_up_key(self, event):
        self.canvas.yview_scroll(-1, "units")

    def _on_down_key(self, event):
        self.canvas.yview_scroll(1, "units")

    def _on_page_up(self, event):
        self.canvas.yview_scroll(-1, "pages")

    def _on_page_down(self, event):
        self.canvas.yview_scroll(1, "pages")

class FuzzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Application Fuzzer")

        # Initialize configuration and statistics
        self.config = FuzzerConfig()
        self.stats = FuzzingStats()

        # Create main scrollable frame
        self.main_frame = ScrollableFrame(root)
        self.main_frame.pack(fill="both", expand=True)

        # Initialize variables
        self.stop_event = Event()
        self.pause_event = Event()
        self.fuzzing_thread = None
        self.os_type = tk.StringVar(value="macos")  # Default to macOS
        # Create reference images directory
        os.makedirs('reference_images', exist_ok=True)
        self.app_launch_delay = tk.IntVar(value=5)
        self.action_delay = tk.DoubleVar(value=0.5)
        self.paused = False

        # Configure pyautogui for faster operation
        pyautogui.FAILSAFE = True
        pyautogui.PAUSE = 0.0
        pyautogui.MINIMUM_DURATION = 0.0
        pyautogui.MINIMUM_SLEEP = 0.0

        # Initialize sequence storage
        self.saved_sequences = {}

        # Set up logging
        self.setup_logging()

        # Build the GUI
        self.setup_gui()

        # Load any saved configurations
        self.load_saved_config()

    def setup_logging(self):
        """Configure logging with custom format"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S'

        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            datefmt=date_format,
            handlers=[
                logging.FileHandler('fuzzer.log'),
                logging.StreamHandler()
            ]
        )

        # Create a logger instance
        self.logger = logging.getLogger('FuzzerGUI')
        self.logger.info("Initializing Application Fuzzer")

    def load_configuration(self):
        """Load saved configuration"""
        try:
            if os.path.exists('fuzzer_config.json'):
                with open('fuzzer_config.json', 'r') as f:
                    config_data = json.load(f)

                # Load settings
                self.screenshot_on_crash.set(config_data.get('screenshot_on_crash', True))
                self.monitor_resources.set(config_data.get('monitor_resources', True))
                self.auto_save.set(config_data.get('auto_save', True))

                # Load timing settings
                timing = config_data.get('timing', {})
                self.app_launch_delay.set(timing.get('launch_delay', 5))
                self.action_delay.set(timing.get('action_delay', 0.5))

                # Load thresholds
                thresholds = config_data.get('thresholds', {})
                self.config.config['cpu_threshold'] = thresholds.get('cpu_threshold', 95)
                self.config.config['memory_threshold'] = thresholds.get('memory_threshold', 90)
                self.config.config['max_crashes'] = thresholds.get('max_crashes', 100)

                messagebox.showinfo("Success", "Configuration loaded successfully")
            else:
                messagebox.showinfo("Info", "No saved configuration found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration: {str(e)}")

    def export_report(self):
        """Export current fuzzing report in different formats"""
        if not hasattr(self, 'stats') or not self.stats.start_time:
            messagebox.showinfo("Info", "No fuzzing session data available to export")
            return

        # Create export directory if it doesn't exist
        export_dir = "exported_reports"
        os.makedirs(export_dir, exist_ok=True)

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        try:
            # Generate report using existing report generator
            report_generator = ReportGenerator(self.stats, self.config)

            # Export HTML report
            html_path = report_generator.generate_html_report()

            # Export JSON data
            json_path = report_generator.export_data('json')

            # Export CSV data
            csv_paths = report_generator.export_data('csv')

            export_info = f"""
    Report exported successfully:
    - HTML Report: {html_path}
    - JSON Data: {json_path}
    - CSV Files: {', '.join(csv_paths) if isinstance(csv_paths, list) else csv_paths}
    """
            messagebox.showinfo("Export Complete", export_info)

            # Open export directory
            if messagebox.askyesno("Open Directory", "Would you like to open the export directory?"):
                if platform.system() == "Windows":
                    os.startfile(export_dir)
                elif platform.system() == "Darwin":  # macOS
                    subprocess.Popen(["open", export_dir])
                else:  # Linux
                    subprocess.Popen(["xdg-open", export_dir])

        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report: {str(e)}")

    def load_saved_config(self):
        """Load saved configuration if available"""
        config_path = 'fuzzer_config.json'
        if os.path.exists(config_path):
            try:
                self.config.load_config(config_path)
                self.logger.info("Loaded saved configuration")
            except Exception as e:
                self.logger.error(f"Error loading configuration: {str(e)}")

    def update_launch_delay_text(self, value):
        """Update launch delay text box when slider moves"""
        try:
            self.launch_delay_entry.delete(0, tk.END)
            self.launch_delay_entry.insert(0, str(round(float(value))))
        except:
            pass

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

    def update_action_delay_text(self, value):
        """Update action delay text box when slider moves"""
        try:
            self.action_delay_entry.delete(0, tk.END)
            self.action_delay_entry.insert(0, str(round(float(value), 3)))
        except:
            pass

    def update_status(self, message):
        """Update status label in a thread-safe way"""
        try:
            # If called from a non-main thread, use after() method
            if threading.current_thread() is not threading.main_thread():
                self.root.after(0, self._update_status_label, message)
            else:
                self._update_status_label(message)
        except Exception as e:
            logging.error(f"Error updating status: {str(e)}")

    def _update_status_label(self, message):
        """Internal method to update the status label"""
        try:
            self.status_label.config(text=f"Status: {message}")
            self.root.update_idletasks()  # More efficient than full update
        except Exception as e:
            logging.error(f"Error updating status label: {str(e)}")

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

    def browse_app(self):
        """Browse for target application"""
        os_type = self.os_type.get()

        if os_type == "macos":
            filetypes = [("Applications", "*.app"), ("All files", "*")]
            # Explicitly set initialdir to /Applications for macOS
            initialdir = "/Applications"
        elif os_type == "windows":
            filetypes = [("Executables", "*.exe"), ("All files", "*")]
            initialdir = os.environ.get("ProgramFiles", "C:\\Program Files")
        else:  # Linux
            filetypes = [("All files", "*")]
            initialdir = "/usr/bin"

        filename = filedialog.askopenfilename(
            title="Select Application",
            initialdir=initialdir,
            filetypes=filetypes
        )

        if filename:
            self.app_path.set(filename)

    def browse_fuzz_list(self):
        """Browse for fuzz list file"""
        filename = filedialog.askopenfilename(
            title="Select Fuzz List",
            filetypes=[
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*")
            ]
        )
        if filename:
            self.fuzz_list_path.set(filename)

    def verify_application_path(self, app_path):
        """Verify application path based on OS type"""
        os_type = self.os_type.get()

        if not os.path.exists(app_path):
            return False, "Application path does not exist"

        if os_type == "macos":
            if app_path.endswith('.app'):
                info_plist = os.path.join(app_path, 'Contents', 'Info.plist')
                if not os.path.exists(info_plist):
                    return False, "Invalid application bundle"
                # Add permission check and user prompt
                messagebox.showinfo("Permission Required",
                    "Please ensure Sublime Text has necessary permissions:\n" +
                    "1. Open System Settings > Privacy & Security > Files and Folders\n" +
                    "2. Add Sublime Text and grant required permissions\n" +
                    "3. Also grant Full Disk Access if needed")
            elif not os.access(app_path, os.X_OK):
                return False, "Application is not executable"

        elif os_type == "windows":
            if not app_path.lower().endswith('.exe'):
                return False, "Not a valid Windows executable"

        else:  # Linux
            if not os.access(app_path, os.X_OK):
                return False, "Application is not executable"

        return True, "Valid application path"

    def browse_log(self):
        """Browse for log file location"""
        filename = filedialog.asksaveasfilename(
            title="Select Log File",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("Log files", "*.log"),
                ("All files", "*")
            ],
            initialfile="fuzz_crashes.txt"
        )
        if filename:
            self.log_path.set(filename)

    def add_initial_mouse_action(self, action_type):
        """Add a mouse action to the initial setup sequence"""
        try:
            self.update_status("Select position for initial setup...")
            self.root.attributes('-alpha', 0.1)  # Make window nearly transparent
            self.root.state('normal')  # Ensure window is visible
            time.sleep(0.5)  # Reduced delay

            # Store current mouse position
            x, y = pyautogui.position()

            if action_type == "DRAG":
                self.root.attributes('-alpha', 1.0)  # Restore visibility
                messagebox.showinfo("Select Second Position",
                                  "Now select the end position for drag operation")
                self.root.attributes('-alpha', 0.1)
                time.sleep(0.5)
                x2, y2 = pyautogui.position()
                self.initial_control_list.insert(tk.END, f"DRAG,{x},{y},{x2},{y2}")
            else:
                self.initial_control_list.insert(tk.END, f"{action_type},{x},{y}")

            self.root.attributes('-alpha', 1.0)  # Restore visibility
            self.update_status("Ready")
        except Exception as e:
            self.root.attributes('-alpha', 1.0)
            messagebox.showerror("Error", f"Failed to add mouse action: {str(e)}")

    def remove_initial_action(self):
        """Remove selected action from initial setup sequence"""
        selection = self.initial_control_list.curselection()
        if selection:
            self.initial_control_list.delete(selection)

    def clear_initial_actions(self):
        """Clear all actions from initial setup sequence"""
        self.initial_control_list.delete(0, tk.END)

    def test_initial_sequence(self):
        """Test the initial setup sequence"""
        if self.initial_control_list.size() == 0:
            messagebox.showwarning("Warning", "No actions in initial sequence")
            return

        try:
            self.execute_initial_setup()
            messagebox.showinfo("Success", "Initial sequence executed successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Error executing initial sequence: {str(e)}")

    def execute_initial_setup(self):
        """Execute the initial setup sequence"""
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
                    elif action_type == "DOUBLE_CLICK":
                        pyautogui.doubleClick(int(parts[1]), int(parts[2]), _pause=False)
                    elif action_type == "DRAG":
                        pyautogui.moveTo(int(parts[1]), int(parts[2]), duration=0, _pause=False)
                        pyautogui.dragTo(int(parts[3]), int(parts[4]), duration=action_delay, _pause=False)

                if action_delay > 0:
                    time.sleep(action_delay)

            except Exception as e:
                logging.error(f"Error executing initial setup action {action}: {str(e)}")
                self.update_status(f"Error in initial setup: {str(e)}")
                raise

    def remove_selected_action(self):
        """Remove selected action from main sequence"""
        selection = self.control_list.curselection()
        if selection:
            self.control_list.delete(selection)

    def clear_actions(self):
        """Clear all actions from main sequence"""
        self.control_list.delete(0, tk.END)

    def move_action_up(self):
        """Move selected action up in the sequence"""
        selection = self.control_list.curselection()
        if selection and selection[0] > 0:
            text = self.control_list.get(selection[0])
            self.control_list.delete(selection[0])
            self.control_list.insert(selection[0]-1, text)
            self.control_list.selection_set(selection[0]-1)

    def move_action_down(self):
        """Move selected action down in the sequence"""
        selection = self.control_list.curselection()
        if selection and selection[0] < self.control_list.size()-1:
            text = self.control_list.get(selection[0])
            self.control_list.delete(selection[0])
            self.control_list.insert(selection[0]+1, text)
            self.control_list.selection_set(selection[0]+1)

    def test_sequence(self):
        """Test the current sequence without fuzzing"""
        if self.control_list.size() == 0:
            messagebox.showwarning("Warning", "No actions in sequence")
            return

        try:
            self.execute_control_sequence("TEST_INPUT")
            messagebox.showinfo("Success", "Sequence executed successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Error executing sequence: {str(e)}")

    def save_current_sequence(self):
        """Save the current sequence to a file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filename:
            sequence_data = {
                'initial_setup': [self.initial_control_list.get(i)
                                for i in range(self.initial_control_list.size())],
                'main_sequence': [self.control_list.get(i)
                                for i in range(self.control_list.size())],
                'timing': {
                    'launch_delay': self.app_launch_delay.get(),
                    'action_delay': self.action_delay.get()
                }
            }

            try:
                with open(filename, 'w') as f:
                    json.dump(sequence_data, f, indent=4)
                messagebox.showinfo("Success", "Sequence saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save sequence: {str(e)}")

    def add_wait_action(self):
        """Add a wait action to the sequence"""
        wait_time = simpledialog.askfloat("Wait Action",
                                         "Enter wait duration (seconds):",
                                         minvalue=0.1, maxvalue=60.0, initialvalue=1.0)
        if wait_time is not None:
            self.control_list.insert(tk.END, f"WAIT,{wait_time}")

    def add_pixel_verification(self):
        """Add a pixel color verification action"""
        self.update_status("Select pixel position...")
        self.root.iconify()
        time.sleep(2)
        x, y = pyautogui.position()
        color = pyautogui.pixel(x, y)
        self.root.deiconify()

        self.control_list.insert(tk.END, f"VERIFY_PIXEL,{x},{y},{color[0]},{color[1]},{color[2]}")
        self.update_status("Ready")

    def add_image_recognition(self):
        """Add an image recognition action"""
        filename = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")]
        )

        if filename:
            confidence = simpledialog.askfloat(
                "Confidence Level",
                "Enter confidence level (0.0-1.0):",
                minvalue=0.0, maxvalue=1.0, initialvalue=0.9
            )

            if confidence is not None:
                relative_path = os.path.relpath(filename, os.path.dirname(__file__))
                self.control_list.insert(tk.END, f"FIND_IMAGE,{relative_path},{confidence}")

    def setup_gui(self):
        """Set up the main GUI components"""
        # Menu Bar
        self.create_menu_bar()

        # OS Selection
        self.create_os_selection()

        # Timing Controls
        self.create_timing_controls()

        # Application Settings
        self.create_application_settings()  # Make sure this line is present

        # Initial Setup Sequence
        self.create_initial_setup_frame()

        # Main Control Sequence
        self.create_main_control_frame()

        # Status and Control
        self.create_status_control_frame()

    def create_menu_bar(self):
        """Create the application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Configuration", command=self.save_configuration)
        file_menu.add_command(label="Load Configuration", command=self.load_configuration)
        file_menu.add_separator()
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Sequence Menu
        sequence_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Sequences", menu=sequence_menu)
        sequence_menu.add_command(label="Save Current Sequence", command=self.save_sequence)
        sequence_menu.add_command(label="Load Sequence", command=self.load_sequence)

        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Clear Logs", command=self.clear_logs)
        tools_menu.add_command(label="View Statistics", command=self.view_statistics)

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)

    def create_os_selection(self):
        """Create OS selection frame"""
        os_frame = ttk.LabelFrame(self.main_frame.scrollable_frame, text="Operating System", padding=10)
        os_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        ttk.Radiobutton(os_frame, text="Linux", variable=self.os_type,
                        value="linux").grid(row=0, column=0, padx=5)
        ttk.Radiobutton(os_frame, text="Windows", variable=self.os_type,
                        value="windows").grid(row=0, column=1, padx=5)
        ttk.Radiobutton(os_frame, text="macOS", variable=self.os_type,
                        value="macos").grid(row=0, column=2, padx=5)

    def create_timing_controls(self):
        """Create timing controls frame"""
        timing_frame = ttk.LabelFrame(self.main_frame.scrollable_frame, text="Timing Controls", padding=10)
        timing_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        # Application Launch Delay
        launch_delay_frame = ttk.Frame(timing_frame)
        launch_delay_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        ttk.Label(launch_delay_frame, text="Application Launch Delay (seconds):").grid(
            row=0, column=0, padx=5, sticky="w")

        launch_delay_slider = ttk.Scale(launch_delay_frame, from_=5, to=30,
                                        orient="horizontal", variable=self.app_launch_delay,
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

        ttk.Label(action_delay_frame, text="Action Execution Delay (seconds):").grid(
            row=0, column=0, padx=5, sticky="w")

        action_delay_slider = ttk.Scale(action_delay_frame, from_=0.0, to=1.0,
                                        orient="horizontal", variable=self.action_delay,
                                        command=self.update_action_delay_text)
        action_delay_slider.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.action_delay_entry = ttk.Entry(action_delay_frame, width=5)
        self.action_delay_entry.grid(row=0, column=2, padx=5)
        self.action_delay_entry.insert(0, str(self.action_delay.get()))
        self.action_delay_entry.bind('<Return>', self.update_action_delay_slider)
        self.action_delay_entry.bind('<FocusOut>', self.update_action_delay_slider)

        # Help text
        help_text = ("Launch Delay: Time to wait after application starts\n"
                    "Action Delay: Time between each action in sequence")
        ttk.Label(timing_frame, text=help_text, justify="left").grid(
            row=2, column=0, columnspan=3, padx=5, pady=5)

    def create_application_settings(self):
        """Create application settings frame"""
        app_frame = ttk.LabelFrame(self.main_frame.scrollable_frame,
                                 text="Application Settings", padding=10)
        app_frame.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")

        # Application Path
        ttk.Label(app_frame, text="Application Path:").grid(row=0, column=0, sticky="w")
        self.app_path = tk.StringVar()
        ttk.Entry(app_frame, textvariable=self.app_path, width=50).grid(
            row=0, column=1, padx=5)
        ttk.Button(app_frame, text="Browse", command=self.browse_app).grid(
            row=0, column=2)

        # Fuzzing List Selection
        ttk.Label(app_frame, text="Fuzz List:").grid(row=1, column=0, sticky="w")
        self.fuzz_list_path = tk.StringVar()
        ttk.Entry(app_frame, textvariable=self.fuzz_list_path, width=50).grid(
            row=1, column=1, padx=5)
        ttk.Button(app_frame, text="Browse", command=self.browse_fuzz_list).grid(
            row=1, column=2)

        # Log File Selection
        ttk.Label(app_frame, text="Log File:").grid(row=2, column=0, sticky="w")
        self.log_path = tk.StringVar(value="fuzz_crashes.txt")
        ttk.Entry(app_frame, textvariable=self.log_path, width=50).grid(
            row=2, column=1, padx=5)
        ttk.Button(app_frame, text="Browse", command=self.browse_log).grid(
            row=2, column=2)

        # Advanced Options
        advanced_frame = ttk.LabelFrame(app_frame, text="Advanced Options", padding=5)
        advanced_frame.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        # Screenshot on crash option
        self.screenshot_on_crash = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_frame, text="Capture Screenshot on Crash",
                       variable=self.screenshot_on_crash).grid(row=0, column=0, padx=5)

        # Resource monitoring option
        self.monitor_resources = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_frame, text="Monitor System Resources",
                       variable=self.monitor_resources).grid(row=0, column=1, padx=5)

        # Auto-save option
        self.auto_save = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_frame, text="Auto-save Results",
                       variable=self.auto_save).grid(row=0, column=2, padx=5)

    def create_initial_setup_frame(self):
        """Create initial setup sequence frame"""
        initial_setup_frame = ttk.LabelFrame(self.main_frame.scrollable_frame,
                                            text="Initial Setup Sequence (Executes Once)",
                                            padding=10)
        initial_setup_frame.grid(row=3, column=0, padx=5, pady=5, sticky="nsew")

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
        initial_action_frame = ttk.LabelFrame(initial_setup_frame,
                                            text="Add Initial Action", padding=5)
        initial_action_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5,
                                sticky="nsew")

        # Mouse Actions for initial setup
        initial_mouse_frame = ttk.LabelFrame(initial_action_frame,
                                            text="Mouse Actions", padding=5)
        initial_mouse_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        ttk.Button(initial_mouse_frame, text="Left Click",
                    command=lambda: self.add_initial_mouse_action("LEFT_CLICK")).grid(
                        row=0, column=0, padx=2, pady=2)
        ttk.Button(initial_mouse_frame, text="Right Click",
                    command=lambda: self.add_initial_mouse_action("RIGHT_CLICK")).grid(
                        row=0, column=1, padx=2, pady=2)
        ttk.Button(initial_mouse_frame, text="Double Click",
                    command=lambda: self.add_initial_mouse_action("DOUBLE_CLICK")).grid(
                        row=1, column=0, padx=2, pady=2)
        ttk.Button(initial_mouse_frame, text="Click and Drag",
                    command=lambda: self.add_initial_mouse_action("DRAG")).grid(
                        row=1, column=1, padx=2, pady=2)

        # List manipulation buttons for initial setup
        initial_list_control_frame = ttk.Frame(initial_setup_frame)
        initial_list_control_frame.grid(row=2, column=0, columnspan=3, pady=5)

        ttk.Button(initial_list_control_frame, text="Remove Selected",
                    command=self.remove_initial_action).grid(row=0, column=0, padx=5)
        ttk.Button(initial_list_control_frame, text="Clear All",
                    command=self.clear_initial_actions).grid(row=0, column=1, padx=5)
        ttk.Button(initial_list_control_frame, text="Test Sequence",
                    command=self.test_initial_sequence).grid(row=0, column=2, padx=5)

    def create_main_control_frame(self):
        """Create main control sequence frame"""
        control_frame = ttk.LabelFrame(self.main_frame.scrollable_frame,
                                        text="Main Control Sequence Builder",
                                        padding=10)
        control_frame.grid(row=4, column=0, padx=5, pady=5, sticky="nsew")

        # Control sequence list with scrollbar
        list_frame = ttk.Frame(control_frame)
        list_frame.grid(row=0, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        self.control_list = tk.Listbox(list_frame, width=50, height=10)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical",
                                command=self.control_list.yview)
        self.control_list.configure(yscrollcommand=scrollbar.set)
        self.control_list.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Action buttons frame
        action_frame = ttk.LabelFrame(control_frame, text="Add Action", padding=5)
        action_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        # Mouse Actions
        mouse_frame = ttk.LabelFrame(action_frame, text="Mouse Actions", padding=5)
        mouse_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        mouse_actions = [
            ("Left Click", "LEFT_CLICK"),
            ("Right Click", "RIGHT_CLICK"),
            ("Double Click", "DOUBLE_CLICK"),
            ("Click and Drag", "DRAG"),
            ("Middle Click", "MIDDLE_CLICK"),
            ("Mouse Move", "MOVE")
        ]

        for i, (text, action) in enumerate(mouse_actions):
            ttk.Button(mouse_frame, text=text,
                        command=lambda a=action: self.add_mouse_action(a)).grid(
                            row=i//2, column=i%2, padx=2, pady=2)

        # Keyboard Actions
        keyboard_frame = ttk.LabelFrame(action_frame, text="Keyboard Actions", padding=5)
        keyboard_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        keyboard_actions = [
            ("Press Enter", "ENTER"),
            ("Ctrl+A (Select All)", "CTRL_A"),
            ("Ctrl+V (Paste Input)", "CTRL_V"),
            ("Ctrl+C (Copy)", "CTRL_C"),
            ("Tab", "TAB"),
            ("Escape", "ESC"),
            ("Delete", "DELETE"),
            ("Backspace", "BACKSPACE"),
            ("Custom Keys...", "CUSTOM")
        ]

        for i, (text, action) in enumerate(keyboard_actions):
            ttk.Button(keyboard_frame, text=text,
                        command=lambda a=action: self.add_keyboard_action(a)).grid(
                            row=i//3, column=i%3, padx=2, pady=2)

        # Special Actions
        special_frame = ttk.LabelFrame(action_frame, text="Special Actions", padding=5)
        special_frame.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")

        special_actions = [
            ("Wait", self.add_wait_action),
            ("Verify Pixel", self.add_pixel_verification),
            ("Find Image", self.add_image_recognition),
            ("Custom Script", self.add_custom_script)
        ]

        for i, (text, command) in enumerate(special_actions):
            ttk.Button(special_frame, text=text, command=command).grid(
                row=0, column=i, padx=2, pady=2)

        # List manipulation buttons
        list_control_frame = ttk.Frame(control_frame)
        list_control_frame.grid(row=3, column=0, columnspan=3, pady=5)

        control_buttons = [
            ("Remove Selected", self.remove_selected_action),
            ("Clear All", self.clear_actions),
            ("Move Up", self.move_action_up),
            ("Move Down", self.move_action_down),
            ("Test Sequence", self.test_sequence),
            ("Save Sequence", self.save_current_sequence)
        ]

        for i, (text, command) in enumerate(control_buttons):
            ttk.Button(list_control_frame, text=text, command=command).grid(
                row=0, column=i, padx=5)

    def create_status_control_frame(self):
        """Create status and control frame"""
        status_frame = ttk.LabelFrame(self.main_frame.scrollable_frame,
                                    text="Status and Control", padding=10)
        status_frame.grid(row=5, column=0, padx=5, pady=5, sticky="nsew")

        # Progress Frame
        progress_frame = ttk.Frame(status_frame)
        progress_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame,
                                            variable=self.progress_var,
                                            maximum=100)
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=5)

        # Status Label
        self.status_label = ttk.Label(status_frame, text="Status: Ready")
        self.status_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        # Statistics Frame
        stats_frame = ttk.Frame(status_frame)
        stats_frame.grid(row=2, column=0, padx=5, pady=5, sticky="ew")

        self.stats_labels = {}
        stats_fields = [
            ("Inputs Processed:", "inputs"),
            ("Crashes Detected:", "crashes"),
            ("Current Memory Usage:", "memory"),
            ("Current CPU Usage:", "cpu")
        ]

        for i, (text, key) in enumerate(stats_fields):
            ttk.Label(stats_frame, text=text).grid(row=i//2, column=i%2*2, padx=5, sticky="e")
            self.stats_labels[key] = ttk.Label(stats_frame, text="0")
            self.stats_labels[key].grid(row=i//2, column=i%2*2+1, padx=5, sticky="w")

        # Control Buttons
        button_frame = ttk.Frame(status_frame)
        button_frame.grid(row=3, column=0, padx=5, pady=5)

        self.start_button = ttk.Button(button_frame, text="Start Fuzzing",
                                        command=self.start_fuzzing)
        self.start_button.grid(row=0, column=0, padx=5)

        self.pause_button = ttk.Button(button_frame, text="Pause",
                                        command=self.toggle_pause, state="disabled")
        self.pause_button.grid(row=0, column=1, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Fuzzing",
                                    command=self.stop_fuzzing, state="disabled")
        self.stop_button.grid(row=0, column=2, padx=5)

    def add_mouse_action(self, action_type):
        """Add a mouse action to the main sequence"""
        try:
            self.update_status("Select position...")
            self.root.attributes('-alpha', 0.1)  # Make window nearly transparent
            self.root.state('normal')  # Ensure window is visible
            time.sleep(0.5)  # Reduced delay

            # Store current mouse position
            x, y = pyautogui.position()

            if action_type == "DRAG":
                self.root.attributes('-alpha', 1.0)
                messagebox.showinfo("Select Second Position",
                                  "Now select the end position for drag operation")
                self.root.attributes('-alpha', 0.1)
                time.sleep(0.5)
                x2, y2 = pyautogui.position()
                self.control_list.insert(tk.END, f"DRAG,{x},{y},{x2},{y2}")
            elif action_type == "MOVE":
                self.control_list.insert(tk.END, f"MOVE,{x},{y}")
            else:
                self.control_list.insert(tk.END, f"{action_type},{x},{y}")

            self.root.attributes('-alpha', 1.0)  # Restore visibility
            self.update_status("Ready")
        except Exception as e:
            self.root.attributes('-alpha', 1.0)
            messagebox.showerror("Error", f"Failed to add mouse action: {str(e)}")

    def add_keyboard_action(self, action_type):
        """Add a keyboard action to the sequence"""
        if action_type == "CUSTOM":
            key_sequence = self.get_custom_key_sequence()
            if key_sequence:
                self.control_list.insert(tk.END, f"CUSTOM_KEYS,{key_sequence}")
        else:
            self.control_list.insert(tk.END, action_type)

    def get_custom_key_sequence(self):
        """Dialog for custom key sequence input"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Custom Key Sequence")
        dialog.transient(self.root)

        ttk.Label(dialog, text="Enter key combination (e.g., ctrl+shift+a):").pack(pady=5)
        entry = ttk.Entry(dialog, width=30)
        entry.pack(pady=5)

        result = [None]

        def on_ok():
            result[0] = entry.get()
            dialog.destroy()

        ttk.Button(dialog, text="OK", command=on_ok).pack(pady=5)

        dialog.wait_window()
        return result[0]

    def add_wait_action(self):
        """Add a wait action to the sequence"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Wait Action")
        dialog.transient(self.root)

        ttk.Label(dialog, text="Wait duration (seconds):").pack(pady=5)
        entry = ttk.Entry(dialog, width=10)
        entry.pack(pady=5)
        entry.insert(0, "1.0")

        def on_ok():
            try:
                duration = float(entry.get())
                self.control_list.insert(tk.END, f"WAIT,{duration}")
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number")

        ttk.Button(dialog, text="OK", command=on_ok).pack(pady=5)

    def add_pixel_verification(self):
        """Add a pixel color verification action"""
        self.update_status("Select pixel position...")
        self.root.iconify()
        time.sleep(2)
        x, y = pyautogui.position()
        color = pyautogui.pixel(x, y)
        self.root.deiconify()

        self.control_list.insert(tk.END, f"VERIFY_PIXEL,{x},{y},{color[0]},{color[1]},{color[2]}")
        self.update_status("Ready")

    def add_image_recognition(self):
        """Add an image recognition action"""
        filename = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")]
        )

        if filename:
            confidence = simpledialog.askfloat(
                "Confidence Level",
                "Enter confidence level (0.0-1.0):",
                minvalue=0.0, maxvalue=1.0, initialvalue=0.9
            )

            if confidence is not None:
                relative_path = os.path.relpath(filename, os.path.dirname(__file__))
                self.control_list.insert(tk.END, f"FIND_IMAGE,{relative_path},{confidence}")

    def find_and_click_image(self, image_path, confidence):
        """Find an image on screen and click it"""
        try:
            # Ensure image path is absolute
            if not os.path.isabs(image_path):
                image_path = os.path.join(os.path.dirname(__file__), image_path)

            # Look for the image on screen
            location = pyautogui.locateCenterOnScreen(
                image_path,
                confidence=confidence,
                grayscale=True  # Faster performance
            )

            if location is None:
                raise Exception(f"Could not find image: {image_path}")

            # Click the center of the found image
            pyautogui.click(location)
            logging.info(f"Successfully found and clicked image: {image_path}")

        except Exception as e:
            logging.error(f"Error in image recognition: {str(e)}")
            raise

    def verify_pixel_color(self, x, y, expected_color):
        """Verify if a pixel matches an expected color"""
        try:
            actual_color = pyautogui.pixel(x, y)

            # Allow small color variations (optional)
            color_threshold = 10

            if not all(abs(a - b) <= color_threshold
                      for a, b in zip(actual_color, expected_color)):
                raise Exception(
                    f"Color mismatch at ({x}, {y}). "
                    f"Expected: {expected_color}, "
                    f"Got: {actual_color}"
                )

            logging.info(f"Pixel color verification passed at ({x}, {y})")

        except Exception as e:
            logging.error(f"Error in pixel verification: {str(e)}")
            raise

    def capture_reference_image(self):
        """Capture a reference image for recognition"""
        try:
            self.update_status("Select area for image capture...")
            self.root.withdraw()
            time.sleep(1)

            # Let user select region
            region = pyautogui.screenshot('temp_reference.png')
            self.root.deiconify()

            # Save with timestamp
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"reference_image_{timestamp}.png"
            region.save(os.path.join('reference_images', filename))

            return filename

        except Exception as e:
            self.root.deiconify()
            logging.error(f"Error capturing reference image: {str(e)}")
            raise

    def add_custom_script(self):
        """Add a custom Python script action"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Custom Script")
        dialog.geometry("600x400")

        text = scrolledtext.ScrolledText(dialog, width=70, height=20)
        text.pack(padx=5, pady=5)

        text.insert(tk.END, "# Available variables:\n"
                            "# fuzz_input - current fuzz input\n"
                            "# self - fuzzer instance\n\n"
                            "def custom_action(fuzz_input, self):\n"
                            "    # Your code here\n"
                            "    pass")

    def save_script():
        script = text.get("1.0", tk.END)
        script_hash = hashlib.md5(script.encode()).hexdigest()
        script_path = os.path.join("scripts", f"script_{script_hash}.py")

        os.makedirs("scripts", exist_ok=True)
        with open(script_path, 'w') as f:
            f.write(script)

        self.control_list.insert(tk.END, f"CUSTOM_SCRIPT,{script_path}")
        dialog.destroy()

        ttk.Button(dialog, text="Save and Add", command=save_script).pack(pady=5)

    def execute_control_sequence(self, fuzz_input):
        """Execute the main control sequence"""
        action_delay = float(self.action_delay.get())

        for i in range(self.control_list.size()):
            if self.stop_event.is_set():
                return

            action = self.control_list.get(i)

            try:
                if "," in action:  # Mouse action or special action with parameters
                    parts = action.split(",")
                    action_type = parts[0]

                    if action_type == "LEFT_CLICK":
                        pyautogui.click(int(parts[1]), int(parts[2]))
                    elif action_type == "RIGHT_CLICK":
                        pyautogui.rightClick(int(parts[1]), int(parts[2]))
                    elif action_type == "DOUBLE_CLICK":
                        pyautogui.doubleClick(int(parts[1]), int(parts[2]))
                    elif action_type == "DRAG":
                        pyautogui.moveTo(int(parts[1]), int(parts[2]))
                        pyautogui.dragTo(int(parts[3]), int(parts[4]), duration=action_delay)
                    elif action_type == "VERIFY_PIXEL":
                        self.verify_pixel_color(int(parts[1]), int(parts[2]),
                                             (int(parts[3]), int(parts[4]), int(parts[5])))
                    elif action_type == "FIND_IMAGE":
                        self.find_and_click_image(parts[1], float(parts[2]))
                else:  # Keyboard action
                    if action == "ENTER":
                        pyautogui.press('enter')
                    elif action == "CTRL_A":
                        pyautogui.hotkey('ctrl', 'a')
                    elif action == "CTRL_V":
                        pyautogui.write(fuzz_input)
                    elif action == "CTRL_C":
                        pyautogui.hotkey('ctrl', 'c')
                    elif action == "TAB":
                        pyautogui.press('tab')
                    elif action == "ESC":
                        pyautogui.press('esc')

                time.sleep(action_delay)

            except Exception as e:
                logging.error(f"Error executing action {action}: {str(e)}")
                self.update_status(f"Error: {str(e)}")
                raise

    def test_sequence(self):
        """Test the current sequence without fuzzing"""
        if self.control_list.size() == 0:
            messagebox.showwarning("Warning", "No actions in sequence")
            return

        try:
            self.execute_control_sequence("TEST_INPUT")
            messagebox.showinfo("Success", "Sequence executed successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Error executing sequence: {str(e)}")

    def test_initial_sequence(self):
        """Test the initial setup sequence"""
        if self.initial_control_list.size() == 0:
            messagebox.showwarning("Warning", "No actions in initial sequence")
            return

        try:
            self.execute_initial_setup()
            messagebox.showinfo("Success", "Initial sequence executed successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Error executing initial sequence: {str(e)}")

    def launch_application(self, app_path):
        """Launch application based on OS type"""
        os_type = self.os_type.get()

        try:
            if os_type == "macos":
                if app_path.endswith('.app'):
                    # Launch app and wait for it to start
                    process = subprocess.Popen(['open', '-W', app_path], shell=False)
                    time.sleep(1)  # Give the app time to initialize
                else:
                    process = subprocess.Popen([app_path], shell=False)
            elif os_type == "windows":
                process = subprocess.Popen([app_path], shell=True)
            else:  # Linux
                process = subprocess.Popen([app_path], shell=False)

            # Verify process started successfully
            if process and process.poll() is None:
                logging.info(f"Successfully launched application: {app_path}")
                return process
            else:
                raise Exception("Process failed to start")

        except Exception as e:
            error_msg = f"Failed to launch application: {str(e)}"
            logging.error(error_msg)
            self.update_status(error_msg)
            messagebox.showerror("Error", error_msg)
            return None

    def log_fuzz_input(self, fuzz_input, status="TESTING"):
        """Log each fuzz input with timestamp"""
        try:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"{timestamp} - Input: {fuzz_input} - Status: {status}"

            # Log to file
            with open(self.log_path.get(), 'a') as f:
                f.write(log_entry + '\n')

            # Update statistics
            self.stats.total_inputs += 1

            # Log using logging module
            logging.info(f"Fuzz Input: {fuzz_input} - Status: {status}")

        except Exception as e:
            logging.error(f"Error logging fuzz input: {str(e)}")

    def verify_process_running(self, process):
        """Verify if the process is still running"""
        try:
            if process is None:
                return False
            return psutil.pid_exists(process.pid)
        except:
            return False

    def start_fuzzing(self):
        """Start the fuzzing process"""
        if not self.validate_inputs():
            return

        self.stats.start_session()
        self.stop_event.clear()
        self.pause_event.clear()

        self.fuzzing_thread = Thread(target=self.fuzz_process)
        self.fuzzing_thread.daemon = True
        self.fuzzing_thread.start()

        self.start_button.config(state="disabled")
        self.pause_button.config(state="normal")
        self.stop_button.config(state="normal")

        self.update_status("Fuzzing started")

    def validate_inputs(self):
        """Validate all required inputs before starting"""
        if not all([self.app_path.get(), self.fuzz_list_path.get(), self.log_path.get()]):
            messagebox.showerror("Error", "Please fill in all required fields")
            return False

        if self.control_list.size() == 0:
            messagebox.showerror("Error", "Please add at least one action to the main sequence")
            return False

        # Verify application path
        is_valid, message = self.verify_application_path(self.app_path.get())
        if not is_valid:
            messagebox.showerror("Error", message)
            return False

        # Verify fuzz list exists and is readable
        try:
            with open(self.fuzz_list_path.get(), 'r', encoding='utf-8', errors='replace') as f:
                first_line = f.readline()
        except Exception as e:
            messagebox.showerror("Error", f"Cannot read fuzz list: {str(e)}")
            return False

        return True

    def toggle_pause(self):
        """Pause or resume fuzzing"""
        if self.paused:
            self.pause_event.clear()
            self.paused = False
            self.pause_button.config(text="Pause")
            self.update_status("Fuzzing resumed")
        else:
            self.pause_event.set()
            self.paused = True
            self.pause_button.config(text="Resume")
            self.update_status("Fuzzing paused")

    def stop_fuzzing(self):
        """Stop the fuzzing process"""
        self.stop_event.set()
        self.update_status("Stopping...")

        if self.fuzzing_thread and self.fuzzing_thread.is_alive():
            self.fuzzing_thread.join(timeout=5.0)

        self.start_button.config(state="normal")
        self.pause_button.config(state="disabled")
        self.stop_button.config(state="disabled")

        self.stats.end_session()
        self.update_status("Ready")

    def monitor_resources(self, process):
        """Monitor system resources of the target process"""
        try:
            proc = psutil.Process(process.pid)
            cpu_percent = proc.cpu_percent(interval=1.0)
            memory_percent = proc.memory_percent()

            # Update GUI labels
            self.stats_labels["cpu"].config(text=f"{cpu_percent:.1f}%")
            self.stats_labels["memory"].config(text=f"{memory_percent:.1f}%")

            return cpu_percent, memory_percent
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None, None

    def detect_crash(self, process):
        """Enhanced crash detection"""
        try:
            if not psutil.pid_exists(process.pid):
                return "Process Terminated"

            proc = psutil.Process(process.pid)

            # Check process status
            if proc.status() == psutil.STATUS_ZOMBIE:
                return "Zombie Process"

            # Check resource usage
            try:
                cpu_percent = proc.cpu_percent(interval=0.1)
                memory_percent = proc.memory_percent()

                # Update stats
                self.stats.add_resource_usage(cpu_percent, memory_percent)

                # Check thresholds
                if cpu_percent > self.config.config['cpu_threshold']:
                    return "CPU Spike"
                if memory_percent > self.config.config['memory_threshold']:
                    return "Memory Leak"

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return "Process Access Error"

            return None

        except psutil.NoSuchProcess:
            return "Process Terminated"
        except Exception as e:
            logging.error(f"Error in crash detection: {str(e)}")
            return None

    def capture_crash_state(self, fuzz_input, crash_type):
        """Capture system state when a crash occurs"""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        crash_dir = os.path.join(self.config.config['crashes_dir'], timestamp)
        os.makedirs(crash_dir, exist_ok=True)

        # Save screenshot
        if self.screenshot_on_crash.get():
            screenshot = pyautogui.screenshot()
            screenshot.save(os.path.join(crash_dir, "screenshot.png"))

        # Save crash information
        crash_info = {
            'timestamp': timestamp,
            'input': fuzz_input,
            'crash_type': crash_type,
            'sequence': [self.control_list.get(i) for i in range(self.control_list.size())],
            'system_info': {
                'os': platform.platform(),
                'python': platform.python_version(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total
            }
        }

        with open(os.path.join(crash_dir, "crash_info.json"), 'w') as f:
            json.dump(crash_info, f, indent=4)

        return crash_dir

    def fuzz_process(self):
        """Main fuzzing process"""
        process = None
        try:
            self.setup_logging()
            app_path = self.app_path.get()

            # Launch application
            self.update_status("Launching application...")
            process = self.launch_application(app_path)

            if not process:
                raise ValueError("Failed to launch application")

            # Wait for application to load
            launch_delay = int(self.app_launch_delay.get())
            self.update_status(f"Waiting {launch_delay} seconds for application to load...")
            time.sleep(launch_delay)

            # Execute initial setup sequence if any
            if self.initial_control_list.size() > 0:
                self.update_status("Executing initial setup sequence...")
                self.execute_initial_setup()
                logging.info("Initial setup sequence completed")

            # Load fuzz inputs
            self.update_status("Loading fuzz list...")
            try:
                with open(self.fuzz_list_path.get(), 'r', encoding='utf-8', errors='replace') as f:
                    inputs = [line.strip() for line in f.readlines()]
                    logging.info(f"Successfully loaded {len(inputs)} inputs using UTF-8 encoding")
            except UnicodeDecodeError:
                with open(self.fuzz_list_path.get(), 'r', encoding='latin-1') as f:
                    inputs = [line.strip() for line in f.readlines()]

            total_inputs = len(inputs)
            self.progress_var.set(0)

            # Main fuzzing loop
            for idx, fuzz_input in enumerate(inputs, 1):
                if self.stop_event.is_set():
                    break

                while self.pause_event.is_set():
                    time.sleep(0.1)
                    if self.stop_event.is_set():
                        break

                # Update progress
                progress = (idx / total_inputs) * 100
                self.progress_var.set(progress)
                self.stats_labels["inputs"].config(text=str(idx))

                self.log_fuzz_input(fuzz_input)

                try:
                    self.execute_control_sequence(fuzz_input)
                except Exception as e:
                    logging.error(f"Error executing sequence for input {fuzz_input}: {str(e)}")
                    continue

                # Check for crashes
                crash_type = self.detect_crash(process)
                if crash_type:
                    crash_msg = f"Crash detected ({crash_type}) with input: {fuzz_input}"
                    logging.error(crash_msg)
                    self.log_fuzz_input(fuzz_input, f"CRASH: {crash_type}")

                    # Capture crash state
                    crash_dir = self.capture_crash_state(fuzz_input, crash_type)
                    self.stats.add_crash(crash_type, {
                        'input': fuzz_input,
                        'crash_dir': crash_dir
                    })

                    self.stats_labels["crashes"].config(text=str(self.stats.crashes))
                    self.update_status(crash_msg)

                    if self.stats.crashes >= self.config.config['max_crashes']:
                        self.update_status("Maximum crash limit reached")
                        break

                    # Restart application
                    process.terminate()
                    time.sleep(2)
                    process = self.launch_application(app_path)
                    time.sleep(launch_delay)

                    if self.initial_control_list.size() > 0:
                        self.execute_initial_setup()

                # Use action delay between inputs
                time.sleep(float(self.action_delay.get()))

        except Exception as e:
            error_msg = f"Error during fuzzing: {str(e)}"
            logging.error(error_msg)
            self.root.after(0, messagebox.showerror, "Error", error_msg)
        finally:
            if process:
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except:
                    pass
            self.generate_report()

    def generate_report(self):
        """Generate comprehensive fuzzing report"""
        try:
            report_generator = ReportGenerator(self.stats, self.config)
            report_path = report_generator.generate_html_report()

            # Export data in different formats
            report_generator.export_data('json')
            report_generator.export_data('csv')

            # Open report in default browser
            if self.auto_save.get():
                webbrowser.open(f'file://{os.path.abspath(report_path)}')

            logging.info(f"Report generated: {report_path}")
        except Exception as e:
            logging.error(f"Error generating report: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")

    def save_sequence(self):
        """Save current sequence to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filename:
            sequence_data = {
                'initial_setup': [self.initial_control_list.get(i)
                                for i in range(self.initial_control_list.size())],
                'main_sequence': [self.control_list.get(i)
                                for i in range(self.control_list.size())],
                'timing': {
                    'launch_delay': self.app_launch_delay.get(),
                    'action_delay': self.action_delay.get()
                }
            }

            try:
                with open(filename, 'w') as f:
                    json.dump(sequence_data, f, indent=4)
                messagebox.showinfo("Success", "Sequence saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save sequence: {str(e)}")
    def load_sequence(self):
        """Load sequence from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'r') as f:
                    sequence_data = json.load(f)

                # Clear existing sequences
                self.initial_control_list.delete(0, tk.END)
                self.control_list.delete(0, tk.END)

                # Load initial setup sequence
                for action in sequence_data.get('initial_setup', []):
                    self.initial_control_list.insert(tk.END, action)

                # Load main sequence
                for action in sequence_data.get('main_sequence', []):
                    self.control_list.insert(tk.END, action)

                # Load timing settings
                timing = sequence_data.get('timing', {})
                self.app_launch_delay.set(timing.get('launch_delay', 5))
                self.action_delay.set(timing.get('action_delay', 0.5))

                messagebox.showinfo("Success", "Sequence loaded successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load sequence: {str(e)}")

    def save_configuration(self):
        """Save current configuration"""
        config_data = {
            'screenshot_on_crash': self.screenshot_on_crash.get(),
            'monitor_resources': self.monitor_resources.get(),
            'auto_save': self.auto_save.get(),
            'timing': {
                'launch_delay': self.app_launch_delay.get(),
                'action_delay': self.action_delay.get()
            },
            'thresholds': {
                'cpu_threshold': self.config.config['cpu_threshold'],
                'memory_threshold': self.config.config['memory_threshold'],
                'max_crashes': self.config.config['max_crashes']
            }
        }

        try:
            with open('fuzzer_config.json', 'w') as f:
                json.dump(config_data, f, indent=4)
            messagebox.showinfo("Success", "Configuration saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")

    def clear_logs(self):
        """Clear log files and crash data"""
        if messagebox.askyesno("Confirm", "This will delete all log files and crash data. Continue?"):
            try:
                # Clear log file
                open(self.log_path.get(), 'w').close()

                # Clear crash directory
                shutil.rmtree(self.config.config['crashes_dir'])
                os.makedirs(self.config.config['crashes_dir'])

                messagebox.showinfo("Success", "Logs and crash data cleared successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear logs: {str(e)}")

    def view_statistics(self):
        """Show detailed statistics window"""
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Fuzzing Statistics")
        stats_window.geometry("600x400")

        # Create notebook for tabbed interface
        notebook = ttk.Notebook(stats_window)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)

        # Summary tab
        summary_frame = ttk.Frame(notebook)
        notebook.add(summary_frame, text='Summary')

        summary_text = (
            f"Total Inputs: {self.stats.total_inputs}\n"
            f"Total Crashes: {self.stats.crashes}\n"
            f"Crash Rate: {self.stats.crashes/self.stats.total_inputs*100:.2f}%\n"
            f"Duration: {datetime.datetime.now() - self.stats.start_time}\n"
        )

        ttk.Label(summary_frame, text=summary_text, justify='left').pack(padx=10, pady=10)

        # Crashes tab
        crashes_frame = ttk.Frame(notebook)
        notebook.add(crashes_frame, text='Crashes')

        crashes_text = scrolledtext.ScrolledText(crashes_frame)
        crashes_text.pack(fill='both', expand=True, padx=5, pady=5)

        for crash in self.stats.crash_details:
            crashes_text.insert(tk.END,
                                f"Time: {crash['time']}\n"
                                f"Type: {crash['type']}\n"
                                f"Details: {crash['details']}\n"
                                f"{'-'*50}\n")

        crashes_text.config(state='disabled')

    def show_documentation(self):
        """Show documentation window"""
        doc_window = tk.Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("800x600")

        doc_text = scrolledtext.ScrolledText(doc_window)
        doc_text.pack(fill='both', expand=True, padx=5, pady=5)

        documentation = """
        Advanced Application Fuzzer Documentation

        1. Getting Started
        - Select your operating system
        - Set timing controls for application launch and actions
        - Choose the target application
        - Prepare a fuzz list file

        2. Creating Test Sequences
        - Initial Setup Sequence: Actions performed once after application launch
        - Main Sequence: Actions performed for each fuzz input

        3. Available Actions
        - Mouse Actions: Left/Right/Double Click, Drag, Move
        - Keyboard Actions: Standard keys and custom combinations
        - Special Actions: Wait, Pixel Verification, Image Recognition

        4. Advanced Features
        - Crash Detection: Process termination, resource usage, responsiveness
        - Resource Monitoring: CPU and memory usage tracking
        - Comprehensive Reporting: HTML reports with charts and statistics

        5. Tips and Best Practices
        - Start with longer delays and reduce as needed
        - Use pixel verification for stability
        - Save and reuse successful sequences
        - Monitor resource usage for memory leaks
        """

        doc_text.insert(tk.END, documentation)
        doc_text.config(state='disabled')

    def show_about(self):
        """Show about dialog"""
        about_text = """
        Advanced Application Fuzzer
        Version 2.0

        A comprehensive GUI application fuzzing tool
        designed for security testing and automation.

        Features:
        - Cross-platform support
        - Advanced crash detection
        - Resource monitoring
        - Comprehensive reporting

        Created by Coalfire
        """

        messagebox.showinfo("About", about_text)

def main():
    root = tk.Tk()
    root.title("Advanced Application Fuzzer")
    root.geometry("1024x768")

    # Set application icon
    try:
        if platform.system() == "Windows":
            root.iconbitmap("fuzzer.ico")
        else:
            img = tk.PhotoImage(file="fuzzer.png")
            root.tk.call('wm', 'iconphoto', root._w, img)
    except:
        pass

    app = FuzzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
