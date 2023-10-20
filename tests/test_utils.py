import inspect

import pytest  # noqa

from waterbutler.utils import inspect_info


@pytest.mark.feature_202210
class TestInspectInfo:
    def test_inspect_info(self):
        current_frame = inspect.currentframe()
        stack_info = inspect.stack()

        # ('/code/tests/test_utils.py', 14, 'test_inspect_info', '/usr/local/lib/python3.6/site-packages/_pytest/python.py', 170, 'pytest_pyfunc_call')
        ret, lineno = inspect_info(current_frame, stack_info), 15  # line 15
        frame_info = inspect.getframeinfo(current_frame)
        stack_first = stack_info[1]
        assert isinstance(ret, tuple)
        assert ret == (frame_info[0], lineno, frame_info[2], stack_first[1], stack_first[2], stack_first[3])
