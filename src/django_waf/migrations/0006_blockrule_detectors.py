from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("django_waf", "0005_blockrule_review_status"),
    ]

    operations = [
        migrations.AddField(
            model_name="blockrule",
            name="detectors",
            field=models.CharField(
                blank=True,
                db_index=True,
                default="",
                help_text=(
                    "Comma-separated, sorted set of anomaly detector names that have ever "
                    "caused a write to this row (e.g. 'detect_cloud_spray,"
                    "detect_unsolved_challenges'). Additive, never overwritten: multiple "
                    "detectors can independently target the same (rule_type, pattern, "
                    "source=AUTO, action) shape, most commonly a shared subnet pattern, and "
                    "each detector's own write only adds its name rather than replacing the "
                    "set. Blank for admin and feed-sourced rules, and for auto-generated rules "
                    "created before this field existed. Lets a detector's own promotion logic "
                    "recognise a rule it has itself previously written, even after another "
                    "detector has since written to the same row (#97)."
                ),
                max_length=255,
                verbose_name="detectors",
            ),
        ),
    ]
