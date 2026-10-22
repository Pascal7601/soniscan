from django.db import migrations

# Frozen copy on purpose: a migration must not change if application code later does.
# A test asserts this equals scanner.scoring.DEFAULT_PARAMS.
V1_PARAMS = {
    "severity_weights": {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0},
    "decay_k": 40,
    "repeat_factor": 0.5,
    "grade_caps": {"critical": 69, "high": 79},
    "grade_bands": {"A": 90, "B": 80, "C": 70, "D": 60},
}


def seed(apps, schema_editor):
    ScoringModel = apps.get_model("findings", "ScoringModel")
    ScoringModel.objects.get_or_create(
        version=1,
        defaults={"params": V1_PARAMS, "notes": "Initial calibration; tune against pilot scans."},
    )


class Migration(migrations.Migration):
    dependencies = [("findings", "0002_rls_tenant_consistency_and_privileges")]

    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]