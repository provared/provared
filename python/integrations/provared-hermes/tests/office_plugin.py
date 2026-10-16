# A small Hermes plugin for the tests, installed beside Provared: tools of an
# invented office, which run inside this program (Hermes's own file tools
# start a shell, which the tests' guard refuses). Each tool writes what it
# was handed into the file named by OFFICE_WORLD, so a test can see which
# calls ran, and with what. Everything here is invented.

import json
import os
import threading
import time


def _note(kind, args):
    with open(os.environ['OFFICE_WORLD'], 'a', encoding='utf-8') as f:
        f.write(json.dumps({'kind': kind, 'args': args}) + '\n')


def _schema(name, description, properties, required):
    return {'name': name, 'description': description,
            'parameters': {'type': 'object', 'properties': properties, 'required': required}}


ORDER = _schema('order_supplies', 'Order office supplies from the stationery supplier.',
                {'item': {'type': 'string'}, 'quantity': {'type': 'integer'}}, ['item', 'quantity'])
MESSAGE = _schema('send_message', 'Send a short message to a person in the office.',
                  {'to': {'type': 'string'}, 'text': {'type': 'string'}}, ['to', 'text'])
NOTHING = _schema('look_around', 'Look around the office.', {}, [])
SLOW = _schema('slow_order', 'Order something that takes a while.', {'item': {'type': 'string'}, 'seconds': {'type': 'number'}}, ['item'])


def order_supplies(args, **_):
    _note('order', args)
    return json.dumps({'ordered': args.get('item'), 'quantity': args.get('quantity')})


def send_message(args, **_):
    _note('message', args)
    return json.dumps({'sent_to': args.get('to')})


def broken(args, **_):
    _note('broken', args)
    raise ValueError('the supplier is closed')


def look_around(args, **_):
    """Calls another tool from inside its own run, as execute_code's sandbox does."""
    from model_tools import handle_function_call
    _note('look', args)
    return handle_function_call('send_message', {'to': 'Sam', 'text': 'from inside'}, task_id='t')


def look_from_a_thread(args, **_):
    """The same, from a thread that carries the call's context, as Hermes starts them."""
    from model_tools import handle_function_call
    from tools.thread_context import propagate_context_to_thread
    out = []
    thread = threading.Thread(target=propagate_context_to_thread(
        lambda: out.append(handle_function_call('send_message', {'to': 'Sam', 'text': 'from a thread'}, task_id='t'))))
    thread.start()
    thread.join(30)
    return out[0]


def order_inside(args, **_):
    """Calls the same kind of tool from inside its own run."""
    from model_tools import handle_function_call
    _note('order', args)
    return handle_function_call('order_supplies', {'item': 'pens', 'quantity': 1}, task_id='t')


def slow_order(args, **_):
    time.sleep(float(args.get('seconds', 1)))
    _note('slow', args)
    return json.dumps({'ordered': args.get('item')})


def register(ctx):
    ctx.register_tool('order_supplies', 'office', ORDER, order_supplies)
    ctx.register_tool('send_message', 'office', MESSAGE, send_message)
    ctx.register_tool('broken_order', 'office', dict(ORDER, name='broken_order'), broken)
    ctx.register_tool('look_around', 'office', NOTHING, look_around)
    ctx.register_tool('look_from_a_thread', 'office', dict(NOTHING, name='look_from_a_thread'), look_from_a_thread)
    ctx.register_tool('order_inside', 'office', dict(NOTHING, name='order_inside'), order_inside)
    ctx.register_tool('slow_order', 'office', SLOW, slow_order)
