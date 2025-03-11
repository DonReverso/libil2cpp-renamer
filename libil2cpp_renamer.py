# IDA imports
import ida_kernwin
import idc
import ida_funcs
# usual imports
import os
from functools import wraps
import copy

START_MSG = """----------------------------------------------------------------------------------------------

 ████   ███  █████      ███  ████   ████████                                                  
░░███  ░░░  ░░███      ░░░  ░░███  ███░░░░███                                                 
 ░███  ████  ░███████  ████  ░███ ░░░    ░███  ██████  ████████  ████████      █████   ██████ 
 ░███ ░░███  ░███░░███░░███  ░███    ███████  ███░░███░░███░░███░░███░░███    ███░░   ███░░███
 ░███  ░███  ░███ ░███ ░███  ░███   ███░░░░  ░███ ░░░  ░███ ░███ ░███ ░███   ░░█████ ░███ ░███
 ░███  ░███  ░███ ░███ ░███  ░███  ███      █░███  ███ ░███ ░███ ░███ ░███    ░░░░███░███ ░███
 █████ █████ ████████  █████ █████░██████████░░██████  ░███████  ░███████  ██ ██████ ░░██████ 
░░░░░ ░░░░░ ░░░░░░░░  ░░░░░ ░░░░░ ░░░░░░░░░░  ░░░░░░   ░███░░░   ░███░░░  ░░ ░░░░░░   ░░░░░░  
                                                       ░███      ░███                         
                                                       █████     █████                        
                                                      ░░░░░     ░░░░░                         
                                                                                         █████
                                                                                        ░░░███
 ████████   ██████  ████████    ██████   █████████████    ██████  ████████     █████████  ░███
░░███░░███ ███░░███░░███░░███  ░░░░░███ ░░███░░███░░███  ███░░███░░███░░███   ░░░░░░░░░   ░███
 ░███ ░░░ ░███████  ░███ ░███   ███████  ░███ ░███ ░███ ░███████  ░███ ░░░     █████████  ░███
 ░███     ░███░░░   ░███ ░███  ███░░███  ░███ ░███ ░███ ░███░░░   ░███        ░░░░░░░░░   ░███
 █████    ░░██████  ████ █████░░████████ █████░███ █████░░██████  █████                  █████
░░░░░      ░░░░░░  ░░░░ ░░░░░  ░░░░░░░░ ░░░░░ ░░░ ░░░░░  ░░░░░░  ░░░░░                  ░░░░░ 
                                                                                              
                                                                                              
                                    Made by Don Reverso =]                                    
                                                                                              
----------------------------------------------------------------------------------------------"""

ENUM_HIST_ID = {
    "CS_FOLDER_PATH": 0
}
FIELD_TYPES = ["public", "private", "protected", "override", "virtual"]
STANDART_TYPES = ["void", "int", "string"]
METHODS = ["get", "set"]

def on_class_changed(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        result = method(self, *args, **kwargs)
        self.set_saved(False)
        return result
    return wrapper

def getFiles(folder):
    files = None
    try:
        files = os.listdir(folder)
    except FileNotFoundError:
        ida_kernwin.msg(f"The system cannot find specified path: {folder}")
        ida_kernwin.warning(f"The system cannot find specified path: {folder}")
    return files


class Function:
    def __init__(self, class_name):
        self.sep_sym = "."                  # symbol to separate name fields
        self.name_fields = [class_name]     # name fields
        self.method = ""                    # method name field (get, set)
        self.ret_type = ""                  # [WORK IN PROGRESS] return type
        self.args_count = 1                 # [WORK IN PROGRESS] arguments count
        self.args = ["int this"]            # [WORK IN PROGRESS] list of arguments
        self.RVA = 0                        # RVA in libil2cpp.so
        self.saved = False                  # Is function saved (for multiple methods, i.e. get + set)
        self.sfx = 0

    @on_class_changed
    def set_sep_sym(self, sym):
        self.sep_sym = sym

    @on_class_changed
    def add_name_field(self, field):
        self.name_fields.append(field)
    
    @on_class_changed
    def set_method(self, method):
        self.method = method

    @on_class_changed
    def set_ret_type(self, type):
        self.ret_type = type

    @on_class_changed
    def add_arg(self, arg):
        self.args.append(arg)
        self.args_count += 1
    
    @on_class_changed
    def set_RVA(self, RVA):                         # RVA is either an int or a hex string
        if type(RVA) == str:
            RVA = int(RVA, 16)
        self.RVA = RVA
    
    def set_saved(self, state):
        self.saved = state
    
    def get_name(self):
        name = self.sep_sym.join(self.name_fields)
        if self.method:
            name += self.sep_sym + self.method
        if self.sfx:
            name += "_" + str(self.sfx)
        return name
    
    def get_method(self):
        return self.method
    
    def get_RVA(self):
        return self.RVA
    
    def is_saved(self):
        return self.saved

    def is_ready(self, opt_fields=False):
        if self.is_saved():
            # print(f"[DEBUG]: is_saved == False; is_saved() == True")
            return False
        if len(self.name_fields) <= 1:
            # print(f"[DEBUG]: is_saved == False; Len <= 1")
            return False
        if self.RVA == 0:
            # print(f"[DEBUG]: is_saved == False; Rva == 0")
            return False
        if opt_fields:
            if self.ret_type == "":
                return False
            if self.args_count != len(self.args):
                return False
        return True
    

    def set_sfx(self, sfx):
        self.sfx = sfx

def parseFile(file_path):
    functions = []

    with open(file_path, mode="rt", encoding="utf-8") as file:
        data = file.read().split("\n")
    file_name = os.path.split(file_path)[-1]
    class_name = os.path.splitext(file_name)[0]

    func = Function(class_name)
    for line in data:
        line = line.split()
        if len(line) == 0:
            continue

        if line[0] in FIELD_TYPES:                                      # ex.: protected override void Awake()
            line = " ".join(line).replace(";", " ").split()
            if func.is_saved() or not func.get_RVA():
                func = Function(class_name)
            elif func.get_method():
                new_func = Function(class_name)
                new_func.set_RVA(func.get_RVA())
                func = new_func
            if "class" in line:
                continue
            while len(line) > 1:
                if "(" in line[0]:
                    break
                if line[0] in STANDART_TYPES:
                    func.set_ret_type(line[0])
                    # TODO: add support for custom types
                line = line[1:]
            name = line[0]
            if "<" in name:
                continue
            if "(" in line[0]:
                name = line[0].split("(")[0]
            func.add_name_field(name)
            # print(f"[DEBUG]: Current name - {func.get_name()}")
            # TODO: add parsing of function's arguments and their types
            continue
        
        elif "".join(line) in METHODS:                                    # ex.: get
            func.set_method("".join(line))
            # print(f"[DEBUG]: Set method {''.join(line)}")
            continue

        elif "[Address(RVA" in line:                                               # ex.: [Address(RVA = "0x1222208", Offset = "0x1221208", VA = "0x1222208", Slot = "5")]
            RVA = line[line.index("[Address(RVA") + 2]
            RVA = RVA.replace("'", "").replace('"', '').replace(",", "")
            func.set_RVA(RVA)
            # print(f"[DEBUG]: Set RVA {RVA}")
            continue
        

        if func.is_ready(opt_fields=False):
            functions.append(copy.copy(func))
            # print(f"[DEBUG]: Saved {func.get_name()}")
            func.set_saved(True)
            if not func.get_method():                       # it's possible that there is another method
                func = Function(class_name)
    return functions


def main():
    print(START_MSG)
    default_folder = os.getcwd()
    folder = ida_kernwin.ask_str(default_folder, ENUM_HIST_ID["CS_FOLDER_PATH"], "Please provide the 𝐟͟𝐮͟𝐥͟𝐥͟ path to the folder with dumped CS classes")
    if folder == None:
        return
    print(f"Chosen folder: {folder}")
    files = getFiles(folder)
    total_count = 0
    renamed_count = 0
    all_functions = []
    for file in files:
        file_path = os.path.join(folder, file)
        if not os.path.isfile(file_path):
            continue
        ext = file_path.split(".")[-1]
        if ext != "cs":
            continue
        functions = parseFile(file_path)
        total_count += len(functions)
        print(f"{file}: parsed {len(functions)} function(s)")
        all_functions.extend(functions)

    all_functions = sorted(all_functions, key=lambda x: x.get_name())
    for i in range(1, len(all_functions)):
        cur = all_functions[i]
        cur_name = cur.get_name()
        prev = all_functions[i - 1]
        prev_name = prev.get_name()

        if prev_name == cur_name:
            all_functions[i].set_sfx(1)
        elif cur_name == "_".join(prev_name.split("_")[:-1]) and prev_name.split("_")[-1].isdigit():
            all_functions[i].set_sfx(int(prev_name.split("_")[-1]) + 1)
        


    for func in all_functions:
        # print(f"[DEBUG]: {hex(func.get_RVA())} - {func.get_name()}")
        if not idc.set_name(func.get_RVA(), func.get_name()):
            print(f"Something in renaming function {func.get_name()} went wrong. Exiting...")
            return
        
        IDA_func = ida_funcs.get_func(func.get_RVA())
        if IDA_func:
            start = IDA_func.start_ea
            if start != func.get_RVA():
                ida_funcs.set_func_end(func.get_RVA(), func.get_RVA())
        IDA_func = ida_funcs.get_func(func.get_RVA())
        if not IDA_func:
            if ida_funcs.add_func(func.get_RVA()):
                print(f"Manually created function at {func.get_RVA()} ({func.get_name()})")
            else:
                print(f"Can't create a function {func.get_RVA()} ({func.get_name()}). Exiting...")
                return
        renamed_count += 1
    print(f"\nTotal count of parsed functions: {total_count}")
    print(f"Total renamed functions: {renamed_count}")


main()