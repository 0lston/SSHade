# Alternative version with advanced red team styling
class SshadeBannerAdvanced:
    @staticmethod
    def display():
        # ANSI color codes - Red/Purple team hacking theme
        DARK_RED = '\033[31m'
        BRIGHT_RED = '\033[91m'
        DARK_PURPLE = '\033[35m'
        BRIGHT_PURPLE = '\033[95m'
        DARK_GRAY = '\033[90m'
        WHITE = '\033[97m'
        BLACK_BG_RED = '\033[41m\033[30m'
        BOLD = '\033[1m'
        DIM = '\033[2m'
        RESET = '\033[0m'
        
        banner = f"""
{BRIGHT_RED}{BOLD}        )\.--.   )\.--.      .'(    /`-.     )\.-.  )\.---.  {RESET}
{DARK_RED}{BOLD}        (   ._.' (   ._.' ,') \  ) ,' _  \  ,'     )(   ,-._( {RESET}
{BRIGHT_PURPLE}{BOLD}        `-.`.    `-.`.  (  '-' ( (  '-' ( (  .-, (  \  '-,   {RESET}
{DARK_PURPLE}{BOLD}        ,_ (  \  ,_ (  \  ) .-.  ) )   _  ) ) '._\ )  ) ,-`   {RESET}
{DARK_RED}{BOLD}        (  '.)  )(  '.)  )(  ,  ) \(  ,' ) \(  ,   (  (  ``-.  {RESET}
{DARK_GRAY}{BOLD}        '._,_.'  '._,_.'  )/    )/ )/    )/ )/ ._.'   )..-.(  {RESET}
{BRIGHT_RED}{BOLD}                                                       {RESET}
        """
        print(banner)

