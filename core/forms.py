from django import forms

class PacketFilterForm(forms.Form):
    from_value = forms.CharField(max_length=100, required=False, label='From Value')
    to_value = forms.CharField(max_length=100, required=False, label='To Value')
