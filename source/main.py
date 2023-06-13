import Mylogin 
import sys
from PyQt5.QtWidgets import QApplication

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = Mylogin.Mylogin()
    win.show()
    sys.exit(app.exec_())