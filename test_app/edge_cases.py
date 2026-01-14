"""Test file for edge cases in hoppy."""

import subprocess


def triple_duplicate():
    """Test call with same variable 3 times."""
    x = 5
    match_this(x, x, x)  # Line 12


def mixed_args():
    """Test mixed literal and variable arguments."""
    match_this("fixed", "variable")  # Line 17


def no_arg_func():
    """Test function with no arguments."""
    pass  # Line 18


def dangerous_test():
    """Test special characters in literal."""
    no_arg_func()  # Line 22 - actual call
    dangerous_func("rm -rf /")  # Line 23


def dangerous_func(val):
    """First OR pattern match."""
    sink_func("data")  # Line 30


def risky_func():
    """Second OR pattern match."""
    sink_func("other_data")  # Line 34


def not_pattern_test():
    """Test NOT pattern exclusion."""
    builtin_eval("safe")  # Line 38 - should be excluded by NOT pattern
    builtin_eval("os.system('rm -rf /')")  # Line 39 - unsafe


def nested_field():
    """Test nested field access."""

    class Inner:
        prop = "value"

    class Obj:
        inner = Inner

    obj = Obj()
    sink_func(obj.inner.prop)  # Line 49


def target_method():
    """Test method context with metavar."""
    subprocess_call_func("arg1")
    subprocess_call_func("arg2")  # Line 54


def same_var_test():
    """Test same var in source and sink."""
    data = "user_data"
    data = get_input_func(data)
    dangerous_func(data)  # Line 59


def different_var_test():
    """Test different vars (no unification)."""
    x = get_input_func("input1")  # noqa: F841
    y = get_input_func("input2")
    dangerous_func(y)  # Line 65 - different variable


def parameter_flow(user_input):
    """Test parameter to sink flow."""
    dangerous_func(user_input)


def multi_sanitizer_test():
    """Test multiple sanitizers."""
    data = get_input_func("tainted")
    # No sanitizer1 - unsafe
    dangerous_func(data)  # Line 71

    data2 = get_input_func("tainted2")
    # Has sanitizer1 - should be excluded by first sanitizer
    clean1 = sanitizer1_func(data2)
    dangerous_func(clean1)  # Line 75

    data3 = get_input_func("tainted3")
    # Has both sanitizers
    clean2 = sanitizer1_func(data3)
    final = sanitizer2_func(clean2)
    dangerous_func(final)  # Line 80


def long_chain():
    """Test long flow chain."""
    val = step1_func("initial")
    val = step2_func(val)
    val = step3_func(val)
    step4_func(val)  # Line 87


def subprocess_test():
    """Test regex in methodFullName."""
    subprocess.call("echo test", shell=True)
    subprocess.run(["echo", "test"], shell=True)


def literal_type_test():
    """Test literal number vs string."""
    custom_func(42)  # Line 94
    custom_func("42")  # Line 95


# Helper functions
def match_this(*args):
    pass


def sink_func(val):
    pass


def get_input_func(name):
    return f"input_{name}"


def builtin_eval(val):
    pass


def subprocess_call_func(val):
    pass


def sanitizer1_func(val):
    return val


def sanitizer2_func(val):
    return val


def step1_func(val):
    return val


def step2_func(val):
    return val


def step3_func(val):
    return val


def step4_func(val):
    pass


def custom_func(val):
    pass
