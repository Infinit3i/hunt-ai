import re


ascii_art = f"""
┓┏       ┏┓┳
┣┫┓┏┏┓╋  ┣┫┃
┛┗┗┻┛┗┗  ┛┗┻
"""


# Original ASCII Art with ANSI Color Codes
full_ascii_art = f"""
┏┳┓┓          ┓┏     •      ┏┓   •┏• •  ┓  ┳     ┓┓•         
 ┃ ┣┓┏┓┏┓┏┓╋  ┣┫┓┏┏┓╋┓┏┓┏┓  ┣┫┏┓╋┓╋┓┏┓┏┓┃  ┃┏┓╋┏┓┃┃┓┏┓┏┓┏┓┏┏┓
 ┻ ┛┗┛ ┗ ┗┻┗  ┛┗┗┻┛┗┗┗┛┗┗┫  ┛┗┛ ┗┗┛┗┗┗┗┻┗  ┻┛┗┗┗ ┗┗┗┗┫┗ ┛┗┗┗ 
                         ┛                           ┛       
"""

infinitei = f"""
██╗███╗   ██╗███████╗██╗███╗   ██╗██╗████████╗██████╗ ██╗
██║████╗  ██║██╔════╝██║████╗  ██║██║╚══██╔══╝╚════██╗██║
██║██╔██╗ ██║█████╗  ██║██╔██╗ ██║██║   ██║    █████╔╝██║
██║██║╚██╗██║██╔══╝  ██║██║╚██╗██║██║   ██║    ╚═══██╗██║
██║██║ ╚████║██║     ██║██║ ╚████║██║   ██║   ██████╔╝██║
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═════╝ ╚═╝
"""

# Function to strip ANSI escape codes
def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

# Stripped versions of the ASCII art
full_ascii_art_stripped = strip_ansi_codes(full_ascii_art)
infinitei_stripped = strip_ansi_codes(infinitei)
