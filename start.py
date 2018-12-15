import multiprocessing
import wx
from audit.gui.mainPanel import MainPanel, get_path_icon

"""
 supported os:
    windows 7,8,10
    linux:
        - debian based distributions
        - rhel based distribution
        - arch based distributions
        - SuSe based distributions
    MacOs X

"""

if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = wx.App(False)
    frame = wx.Frame(None, title='Audit')
    frame.SetMinSize((500, 430))
    MainPanel(frame)
    icon = wx.Icon()
    icon.CopyFromBitmap(wx.Bitmap(get_path_icon() + "/icon.ico", wx.BITMAP_TYPE_ANY))
    frame.SetIcon(icon)
    frame.Show()
    app.MainLoop()