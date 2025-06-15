from django import template

register = template.Library()

@register.filter(name='add_attr')
def add_attr(field, args):
    attrs = {}
    for arg in args.split(','):
        key, val = arg.split(':')
        attrs[key] = val
    return field.as_widget(attrs=attrs)


@register.filter(name='add_class')
def add_class(field, css):
    return field.as_widget(attrs={"class": css})