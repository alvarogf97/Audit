import multiprocessing
import os
import sys
import warnings
import wx
import re
from audit.core import environment
from queue import Queue
from audit.core.agent import Agent
from audit.database.user import init_db
from audit.gui.userPanel import UserPanel


class MainPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent)
        self.parent = parent
        self.start_button = wx.Button(self, label="Start", pos=(10, 10), size=(151, 30))
        self.port_label = wx.StaticText(self, label="Port:", pos=(10, 52))
        self.port_edit = wx.TextCtrl(self, value="5000", pos=(60, 50), size=(100, 20))
        self.email_label = wx.StaticText(self, label="Email:", pos=(10, 92))
        self.email_edit = wx.TextCtrl(self, value="", pos=(60, 90), size=(100, 20))
        self.open_port_checkbox = wx.CheckBox(self, label="Open router port", pos=(10, 130))
        self.send_email_checkbox = wx.CheckBox(self, label="Send email", pos=(150, 130))
        self.user_button = wx.Button(self, label="Users", pos=(320,125), size=(151,30))
        self.server_info = wx.TextCtrl(self, pos=(170, 10), size=(300, 105), style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.label = wx.StaticText(self, label="Server log:", pos=(227, 160))
        self.logger = wx.TextCtrl(self, pos=(10, 180), size=(460, 200), style=wx.TE_MULTILINE | wx.TE_READONLY)

        self.Bind(wx.EVT_BUTTON, self.on_click_start_button, self.start_button)
        self.Bind(wx.EVT_BUTTON, self.on_click_user_button, self.user_button)
        self.Bind(wx.EVT_WINDOW_DESTROY, self.on_close)
        self.Bind(wx.EVT_CHECKBOX, self.open_port_checkbox_click, self.open_port_checkbox)
        self.Bind(wx.EVT_CHECKBOX, self.send_email_checkbox_click, self.send_email_checkbox)

        self.timer = wx.Timer(self, 0)
        self.Bind(wx.EVT_TIMER, self.check_queue)
        self.timer.Start(1000)  # 1 second interval
        self.email_edit.Enable(False)
        self.agent_process = None
        self.started = False
        self.queue = None
        self.is_open_check = False
        self.is_send_check = False

        self.user_frame = wx.Frame(None, title='Users')
        self.user_frame.SetMinSize((380, 360))
        self.user_panel = UserPanel(self.user_frame, self)
        icon = wx.Icon()
        icon.CopyFromBitmap(wx.Bitmap(get_path_icon() + "/icon.ico", wx.BITMAP_TYPE_ANY))
        self.user_frame.SetIcon(icon)
        environment.Environment()
        init_db()

    def update_server_info(self, msg):
        self.server_info.AppendText(msg + "\n")

    def update_logger(self, msg):
        self.logger.AppendText(msg + "\n")

    def clean_loggers(self):
        self.server_info.SetValue("")
        self.logger.SetValue("")

    def on_click_start_button(self, event):
        self.clean_loggers()
        if not self.started:
            if self.validate():
                queue = multiprocessing.Queue()
                self.agent_process = multiprocessing.Process(target=start_agent,
                                                             args=(queue,
                                                                   int(self.port_edit.GetValue()),
                                                                   self.is_open_check,
                                                                   self.is_send_check,
                                                                   self.email_edit.GetValue()))
                self.agent_process.start()
                self.started = True
                self.queue = queue
                self.start_button.SetLabel("Stop")
                self.user_button.Enable(False)
            else:
                self.update_logger("wrong inputs")
        else:
            self.start_button.SetLabel("Start")
            self.started = False
            self.agent_process.terminate()
            self.queue.close()
            self.queue = None
            self.user_button.Enable(True)

    def on_close(self, event):
        if self.agent_process is not None and self.agent_process.is_alive():
            self.agent_process.terminate()

    def check_queue(self, event):
        if self.queue is not None:
            try:
                last_msg = self.queue.get(timeout=0.1)
                while last_msg:
                    last_msg_split = last_msg.split("@")
                    if last_msg_split[0] == "server_info":
                        self.update_server_info(last_msg_split[1])
                    else:
                        self.update_logger(last_msg_split[1])
                    last_msg = self.queue.get(timeout=0.1)
            except Exception as e:
                warnings.warn(str(e))

    def open_port_checkbox_click(self, event):
        self.is_open_check = not self.is_open_check

    def send_email_checkbox_click(self, event):
        self.is_send_check = not self.is_send_check
        if self.is_send_check:
            self.email_edit.Enable(True)
        else:
            self.email_edit.Enable(False)

    def validate(self):

        result = True
        try:
            port = int(self.port_edit.GetValue())
        except Exception as e:
            warnings.warn(str(e))
            result = False

        if self.is_send_check \
                and result \
                and not re.match(r"[^@]+@[^@]+\.[^@]+.", self.email_edit.GetValue()):
            result = False

        return result

    def on_click_user_button(self, event):
        self.parent.Hide()
        self.user_frame.Show()

    def close_user_panel(self, event):
        self.user_frame.Hide()
        self.parent.Show()

    def on_close_user_panel(self, event):
        self.user_frame = wx.Frame(None, title='Users')
        self.user_frame.SetMinSize((500, 430))
        self.user_panel = UserPanel(self.user_frame, self)
        icon = wx.Icon()
        icon.CopyFromBitmap(wx.Bitmap(get_path_icon() + "/icon.ico", wx.BITMAP_TYPE_ANY))
        self.user_frame.SetIcon(icon)
        self.parent.Show()


def start_agent(queue: Queue, port: int, open_on_router: bool, send_mail: bool, mail: str):
    agent = Agent(port, queue, open_on_router=open_on_router, send_mail=send_mail, mail=mail)
    agent.serve_forever()


def get_path_icon():
    if hasattr(sys, "_MEIPASS"):  # Pyinstaller arguments
        return os.path.join(sys._MEIPASS, "icon")
    else:
        return "./builder/icon"
