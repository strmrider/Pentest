from .protocols import types
from . import parser
import time

class Packet:
    def __init__(self):
        self.layers = []
        self.dissection_time = None
        self.length = 0

    def add_layer(self, layer):
        if layer.type == types.Layers.RAW or layer not in self:
            self.layers.append(layer)
            self.length += len(layer.pack())
        else:
            raise Exception("Layer is already in packet")

    def add_layers(self, layers):
        for layer in layers:
            self.add_layer(layer)

    def clean_add(self, layers):
        self.clear()
        self.add_layers(layers)

    def remove_layer_per_index(self, index):
        self.layers.pop(index)

    def remove_layer_per_type(self, layer_type):
        for layer in self.layers:
            if layer.type == layer_type:
                self.layers.remove(layer)
                break

    def get_layers(self):
        return self.layers

    def clear(self):
        self.layers = []
        self.length = 0

    @staticmethod
    def __get_packed_length(pack):
        total_length = 0
        for packed_layer in pack:
            total_length += len(packed_layer)

        return total_length

    def pack(self):
        packs = []
        for layer in reversed(self.layers):
            if layer.type == types.Layers.IP:
                layer.add_payload_length(self.__get_packed_length(packs))
            elif layer.type == types.Layers.UDP:
                layer.add_length(self.__get_packed_length(packs))
            packs.append(layer.pack())
        packs.reverse()

        return b''.join(packs)

    def dissect(self, raw_data, wlan=False):
        self.layers.clear()
        self.dissection_time = time.time()
        self.length = len(raw_data)
        self.layers = parser.parse(raw_data, wlan)

    def __contains__(self, layer_type):
        for layer in self.layers:
            if layer.type == layer_type:
                return True
        return False

    def __getitem__(self, request_layer):
        for layer in self.layers:
            if layer.type == request_layer:
                return layer
        return None

    def __len__(self):
        total_length = 0
        for layer in self.layers:
            total_length += len(layer.pack())

        return total_length

    def __str__(self):
        """
        returns packet's size in bytes and layers list
        """
        layers = " -> ".join([types.Layers.get_name(layer.type) for layer in self.layers])
        return "Size is {} bytes\nLayers: {}".format(len(self), layers)

    def print(self, summary=False):
        for layer in self.layers:
            if summary:
                print (layer.summary)
            else:
                print (layer)
        print ('\n'+('#'*30) + '\n')
