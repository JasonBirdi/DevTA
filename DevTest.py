import os
import serial
from kivy.app import App
from kivy.uix.screenmanager import Screen
from kivy.config import Config
Config.set('graphics', 'width', '800')
Config.set('graphics', 'height', '750')
from comms_packet import PacketExport

class TestScreen(Screen):
    # ser = serial.Serial(os.environ['HOME'] + '/serial1') -> used before in company for ease of all users
    ser = serial.Serial(os.ctermid())
    print(ser.name)
    
    def button_pressed(self, btn):
        print(btn.text)

    def button_released(self, btn):
        if btn.text == 'IR Broken Event':
            file = open("fake_cam.sh", 'w')
            file.write("1")
            file.close()
        elif btn.text == 'IR Clear Event':
            file = open("fake_cam.sh", 'w')
            file.write("0")
            file.close()
        elif (btn.text == 'Button Pressed Event'):
            os.system('fake_gpio.py')
        elif (btn.text == 'Button Pressed Ack') or (btn.text == 'IR Broken Ack') or (btn.text == 'IR Clear Ack'):
            pass
        else:
            packet = PacketExport.packet_assembly(btn.type, btn.i_d, btn.byte)
            print(packet.hex())
            self.ser.write(packet)
    
    def close_serial(self, btn):
        print('Serial closed:' + os.environ['HOME'] + '/serial1')
        self.ser.close()


class DevTestApp(App):
    def build(self):
        return TestScreen()

if __name__ == '__main__':
    DevTestApp().run()