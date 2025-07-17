from __future__ import annotations
import typer

from .wizard       import wizard_cmd
from .auto_wizard  import auto_wizard_cmd

app = typer.Typer(help="Mephala interactive back-porting CLI")
app.command("wizard")(wizard_cmd)
app.command("auto-wizard")(auto_wizard_cmd)


def main() -> None: 
    app()


if __name__ == "__main__":
    main()
