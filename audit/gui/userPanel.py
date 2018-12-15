import warnings
import wx
from audit.database.user import User


class UserPanel(wx.Panel):
    def __init__(self, parent, main_panel):
        wx.Panel.__init__(self, parent)
        self.name_label = wx.StaticText(self, label="Name:", pos=(10, 22))
        self.name_edit = wx.TextCtrl(self, value="", pos=(110, 20), size=(230, 20))
        self.password_label = wx.StaticText(self, label="Password:", pos=(10, 52))
        self.password_edit = wx.TextCtrl(self, value="", pos=(110, 50), size=(230, 20),style=wx.TE_PASSWORD)
        self.password_again_label = wx.StaticText(self, label="Repeat password:", pos=(10, 82))
        self.password_again_edit = wx.TextCtrl(self, value="", pos=(110, 80), size=(230, 20), style=wx.TE_PASSWORD)
        self.info = wx.TextCtrl(self, pos=(10, 170), size=(330, 100), style=wx.TE_MULTILINE | wx.TE_READONLY)

        self.create_button = wx.Button(self, label="Create", pos=(10, 120), size=(151, 30))
        self.delete_button = wx.Button(self, label="Delete", pos=(190, 120), size=(151, 30))
        self.close_button = wx.Button(self, label="Close", pos=(10, 280), size=(330, 30))
        self.Bind(wx.EVT_BUTTON, main_panel.close_user_panel , self.close_button)
        self.Bind(wx.EVT_WINDOW_DESTROY, main_panel.on_close_user_panel)
        self.Bind(wx.EVT_BUTTON, self.on_click_create, self.create_button)
        self.Bind(wx.EVT_BUTTON, self.on_click_delete, self.delete_button)

    def on_click_create(self, event):
        self.info.SetValue("")
        if self.validate():
            try:
                User.create_user(name=str(self.name_edit.GetValue()), password=str(self.password_edit.GetValue()))
                self.info.AppendText("User created correctly\n")
            except Exception as e:
                warnings.warn(str(e))
                self.info.AppendText("User already exists\n")

    def on_click_delete(self, event):
        self.info.SetValue("")
        if self.validate():
            try:
                User.delete_user(name=str(self.name_edit.GetValue()), password=str(self.password_edit.GetValue()))
                self.info.AppendText("User delete correctly\n")
            except Exception as e:
                warnings.warn(str(e))
                self.info.AppendText("User does not exist\n")


    def validate(self):
        validate = True
        name = str(self.name_edit.GetValue())
        password = str(self.password_edit.GetValue())
        password_repeat = str(self.password_again_edit.GetValue())
        if name == "":
            validate = False
            self.info.AppendText("name cannot be blank\n")
        if password == "":
            validate = False
            self.info.AppendText("password cannot be blank\n")
        if password != password_repeat:
            validate = False
            self.info.AppendText("Passwords do not match\n")
        return validate
