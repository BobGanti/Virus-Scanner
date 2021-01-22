from tkinter import *
from tkinter import filedialog
import tkinter as tk
from tkinter import ttk
import requests
from tkinter.messagebox import *


LARGE_FONT = ('Verdana', 12)
XLARGE_FONT = ('Verdana', 16)
labelO = ""
# app set-up
class VirusTotalReportParser(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        container = tk.Frame(self)
        tk.Tk.wm_title(self, 'VirusTotalReportParser')
        tk.Tk.iconbitmap(self,)
        container.pack(side='top', fill='both', expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (MenuPage, FileAnalysis, UrlAnalysis):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky='nsew')

        self.show_frame(MenuPage)

    def show_frame(self, controller):  # display frames
        frame = self.frames[controller]
        frame.tkraise()

    def quitting(self, controller):
        sys.exit()

class MenuPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        tk.Frame.configure(self, bg='lightgray')
        label = tk.Label(self, text="MENU", bg='lightgray', font = XLARGE_FONT)
        label.pack(pady=20, padx=10)

        frame1 = tk.Frame(self, bg='lightgray')
        frame1.pack()
        self.btn1 = Button(frame1, text="File Analysis", width=20,bg='gray', command=lambda: controller.show_frame(FileAnalysis))
        self.btn1.pack(side='left', fill=X, padx=10, pady=25)
        self.btn2 = Button(frame1, text="URL Analysis", width=20, bg='gray', command=lambda: controller.show_frame(UrlAnalysis))
        self.btn2.pack(side='left', fill=X, padx=10, pady=25)

        frame2 = tk.Frame(self)
        frame2.pack()
        self.btn_quit = Button(frame2, text="Quit", width=20, bg='red', command=lambda: controller.quitting(MenuPage))
        self.btn_quit.pack()

class FileAnalysis(tk.Frame):
    def __init__(self, parent, controller):
        self.controller = controller
        tk.Frame.__init__(self, parent)
        tk.Frame.configure(self, bg='lightgray')
        label1 = tk.Label(self, text="File Analysis", bg='lightgray', font=XLARGE_FONT)
        label1.pack(pady=20, padx=10)

        frame1 = tk.Frame(self, bg='lightgray')
        frame1.pack()
        btn_chooseFile = tk.Button(frame1, text="Choose file", width=20, bg='lightgray', command=lambda: choose_file())
        btn_chooseFile.pack(side='left', fill=X, padx=10, pady=25)
        self.label2 = tk.Label(frame1, text="", width=75, bg='green', bd=1)
        self.label2.pack(side='left', fill=X)
        btn_scan = tk.Button(frame1, text="Scan", bg='gray', command=lambda: send_file())
        btn_scan.pack(side='left', fill=X)

        frame2 = tk.Frame(self, bg='lightgray')
        frame2.pack()
        btn_back = Button(frame2, text="<--Menu", width=20, bg='gray', command=lambda: back())
        btn_back.pack(side='left', fill=X, padx=5, pady=5)
        btn_fward = Button(frame2, text="Url Analysis-->", width=20, bg='gray', command=lambda: forward())
        btn_fward.pack(side='left', fill=X, padx=5, pady=5)
        btn_quit = Button(frame2, text="Quit", width=20, bg='red', command=lambda: self.quit())
        btn_quit.pack(side='left', fill=X, padx=5, pady=5)

        def back():
            controller.show_frame(MenuPage)

        def forward():
            controller.show_frame(UrlAnalysis)

        def choose_file():
            filename = filedialog.askopenfilename()
            self.label2['text'] = filename

        def send_file():
            path = self.label2['text']
            if (path == ""):
                showerror('Error!', 'You have not chosen a file')
            else:
                self.scan_file(path)

    def scan_file(self, path):
        info_board_frame = Frame(self, bg='lightgray')
        info_board_frame.pack(fill=BOTH, padx=10, expand=1)
        frame = tk.Frame(info_board_frame, bg='lightgray')
        frame.pack()
        lbl1 = tk.Label(frame, text='FILE SCAN REPORT STAT:', bg='lightgray', font=LARGE_FONT)
        lbl1.pack(side='left', fill=X, pady=10, padx=5)
        lbl2 = tk.Label(frame, text='', bg='lightgray', font=LARGE_FONT)
        lbl2.pack(side='left', fill=X, pady=10, padx=5)
        lbl2.configure(fg='green')

        self.yscrollbar = Scrollbar(info_board_frame)
        self.yscrollbar.pack(side=RIGHT, fill=Y)

        self.lbox = Listbox(info_board_frame, height=17, bd=2, relief='sunken')
        self.lbox.pack(fill='x', expand=False)

        self.lbox.config(yscrollcommand=self.yscrollbar.set)
        self.yscrollbar.config(command=self.lbox.yview)

        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': f'{api_key}'}
        files = {'file': ('myfile', open(path, 'rb'))}

        response = requests.post(url, files=files, params=params)
        res_dict = response.json()
        id = res_dict['scan_id']
        resourse = res_dict['resource']
        self.lbox.delete(0, END)
        self.lbox.insert(END, f'Scan Id: {res_dict["scan_id"]}')
        self.lbox.insert(END, f'Sha1: {res_dict["sha1"]}')
        self.lbox.insert(END, f'Resource: res_dict["resource"]')
        self.lbox.insert(END, f'Response Code: {res_dict["response_code"]}')
        self.lbox.insert(END, f'Sha256: {res_dict["sha256"]}')
        self.lbox.insert(END, f'Permalink: {res_dict["permalink"]}')
        self.lbox.insert(END, f'md5: {res_dict["md5"]}')
        self.lbox.insert(END, f'Verbose Msg: {res_dict["verbose_msg"]}')
        self.lbox.insert(END, '___________________________________________________________________________________')
        self.lbox.insert(END, '')

    def get_file_report(self, resource):
        info_board_frame = Frame(self, bg='lightgray')
        info_board_frame.pack(fill=BOTH, padx=10, expand=1)
        frame = tk.Frame(info_board_frame, bg='lightgray')
        frame.pack()
        lbl1 = tk.Label(frame, text='FILE SCAN REPORT STAT:', bg='lightgray', font=LARGE_FONT)
        lbl1.pack(side='left', fill=X, pady=10, padx=5)
        lbl2 = tk.Label(frame, text='', bg='lightgray', font=LARGE_FONT)
        lbl2.pack(side='left', fill=X, pady=10, padx=5)
        lbl2.configure(fg='green')

        self.yscrollbar = Scrollbar(info_board_frame)
        self.yscrollbar.pack(side=RIGHT, fill=Y)

        self.lbox = Listbox(info_board_frame, height=17, bd=2, relief='sunken')
        self.lbox.pack(fill='x', expand=False)

        self.lbox.config(yscrollcommand=self.yscrollbar.set)
        self.yscrollbar.config(command=self.lbox.yview)

        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': f'{api_key}', 'resource': resource}
        response = requests.get(url, params=params)
        res_dict = response.json()
        #date = res_dict['scan_date']
        id = res_dict['scan_id']
        resourse = res_dict['resource']
        self.lbox.delete(0, END)
       # self.lbox.insert(END, f'Scan date --> {date}')
        self.lbox.insert(END, f'Scan Id: {scan_id}')
        self.lbox.insert(END, f'Sha1: {sha1}')
        self.lbox.insert(END, f'Resource: {resource}')
        self.lbox.insert(END, f'Response Code: {response_code}')
        self.lbox.insert(END, f'Sha256: {sha256}')
        self.lbox.insert(END, f'Permalink: {permalink}')
        self.lbox.insert(END, f'md5: {md5}')
        self.lbox.insert(END, f'Verbose Msg: {verbose_msg}')
        self.lbox.insert(END, '___________________________________________________________________________________')
        self.lbox.insert(END, '')
        count = 0
        for key, value in res_dict['scans'].items():
            if(value['detected']):
                lbl2.configure(fg='red')
                self.lbox.insert(END, key, ':', value['result'])
                count += 1

        if(count > 0):
            if(count == 1):
                lbl2['text'] = "This File contains Malware"
            else:
                lbl2['text'] = "This file contains Malwares"
        else:
            lbl2['text'] = "The file is clean"
    def quit(self):
        sys.exit()

class UrlAnalysis(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        tk.Frame.configure(self, bg='lightgray')
        label = tk.Label(self, text="URL Analysis", bg='lightgray', font=XLARGE_FONT)
        label.pack(pady=20, padx=10)

        frame1 = tk.Frame(self, bg='lightgray')
        frame1.pack()
        label = tk.Label(frame1, text="Enter url", width=20, bg='lightgray')
        label.pack(side='left', fill=X, padx=10, pady=25)
        self.entry = tk.Entry(frame1, width=100, name="url_entry")
        self.entry.pack(side='left', fill=X, pady=25)
        btn_scan = tk.Button(frame1, text="Scan", bg='gray', command=lambda: send_url())
        btn_scan.pack(side='left', fill=X)

        frame2 = tk.Frame(self, bg='lightgray')
        frame2.pack()
        button1 = tk.Button(frame2, text="<--File Analysis", width=20, bg='gray', command=lambda: controller.show_frame(FileAnalysis))
        button1.pack(side='left', fill=X, padx=5, pady=5)
        button2 = tk.Button(frame2, text="Menu-->", width=20, bg='gray', command=lambda: controller.show_frame(MenuPage))
        button2.pack(side='left', fill=X, padx=5, pady=5)
        self.btn_quit = Button(frame2, text="Quit", width=20, bg='red', command=lambda: controller.quitting(UrlAnalysis))
        self.btn_quit.pack(side='left', fill=X, padx=5, pady=5)

        def send_url():
            path = self.entry.get()
            if(path == ""):
                showerror('Error!', 'You have not entered a url')
            else:
                self.upload_url(path)

    def upload_url(self, path):
        url = 'https://www.virustotal.com/vtapi/v2/url/scan'
        params = {'apikey': '{api_key}', 'url': path}

        response = requests.post(url, data=params)
        res_dict = response.json()
        resource = res_dict['resource']
        self.entry.delete(0, END)

        self.get_url_report(resource)

    def get_url_report(self, resource):
        info_board_frame = Frame(self, bg='lightgray')
        info_board_frame.pack(fill=BOTH, padx=10, expand=1)
        frame = tk.Frame(info_board_frame, bg='lightgray')
        frame.pack()
        lbl1 = tk.Label(frame, text='URL SCAN REPORT STAT:', bg='lightgray', font=LARGE_FONT)
        lbl1.pack(side='left', fill=X, pady=10, padx=5)
        lbl2 = tk.Label(frame, text='', bg='lightgray', font=LARGE_FONT)
        lbl2.pack(side='left', fill=X, pady=10, padx=5)
        lbl2.configure(fg='green')

        self.yscrollbar = Scrollbar(info_board_frame)
        self.yscrollbar.pack(side=RIGHT, fill=Y)

        self.lbox = Listbox(info_board_frame, height=17, bd=2, relief='sunken')
        self.lbox.pack(fill='x', expand=False)

        self.lbox.config(yscrollcommand=self.yscrollbar.set)
        self.yscrollbar.config(command=self.lbox.yview)

        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': '{api_key}', 'resource': resource}
        response = requests.get(url, params=params)
        res_dict = response.json()

        date = res_dict['scan_date']
        id = res_dict['scan_id']
        resourse = res_dict['resource']
        self.lbox.delete(0, END)
        self.lbox.insert(END, f'Scan date --> {date}')
        self.lbox.insert(END, f'Scan Id --> {id}')
        self.lbox.insert(END, f'Resource --> {resource}')
        self.lbox.insert(END, '___________________________________________________________________________________')
        self.lbox.insert(END, '')
        count = 0

        for key, value in res_dict['scans'].items():
            if(value['detected'] == True):
                stat = "Site contains Malware(s)"
                lbl2.configure(fg='red')
                self.lbox.insert(END, key, ':', value['result'])
                count += 1

        if (count > 0):
            if (count == 1):
                lbl2['text'] = "This File contains Malware"
            else:
                lbl2['text'] = "This file contains Malwares"
        else:
            bl2['text'] = "The file is clean"

app = VirusTotalReportParser()
app.geometry('980x520')

app.mainloop()
