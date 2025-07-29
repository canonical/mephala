import textwrap
from mephala.core.diff.hunk import Hunk

def test_generate_actions_from_minimal_patch():
    raw = textwrap.dedent(
        """\
        --- a/foo.c
        +++ b/foo.c
        @@ -10,3 +10,4 @@
         int x = 0;
        -int y = 1;
        +int y = 2;
        """
    )
    hunk = Hunk.from_diff_lines(raw.splitlines())
    actions = hunk.generate_actions()

    assert len(actions) == 2              # 1 deletion + 1 insertion
    assert actions[0].action_type.name == "DELETION"
    assert actions[1].action_type.name == "INSERTION"
