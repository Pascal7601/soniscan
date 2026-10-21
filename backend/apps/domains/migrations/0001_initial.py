import django.db.models.deletion
import django.db.models.functions.text
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('accounts', '0002_memberships_rls'),
    ]

    operations = [
        migrations.CreateModel(
            name='Domain',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('fqdn', models.CharField(max_length=253)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('verified', 'Verified'), ('expired', 'Expired'), ('suspended', 'Suspended')], default='pending', max_length=20)),
                ('verified_at', models.DateTimeField(blank=True, null=True)),
                ('verified_method', models.CharField(blank=True, choices=[('dns_txt', 'Dns Txt'), ('http_file', 'Http File')], default='', max_length=20)),
                ('reverify_due', models.DateTimeField(blank=True, null=True)),
                ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.tenant')),
            ],
            options={
                'db_table': 'domains',
            },
        ),
        migrations.CreateModel(
            name='DomainVerification',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('method', models.CharField(choices=[('dns_txt', 'Dns Txt'), ('http_file', 'Http File')], max_length=20)),
                ('token_hash', models.BinaryField()),
                ('expires_at', models.DateTimeField()),
                ('checked_at', models.DateTimeField(blank=True, null=True)),
                ('result', models.CharField(choices=[('pending', 'Pending'), ('verified', 'Verified'), ('failed', 'Failed'), ('expired', 'Expired')], default='pending', max_length=20)),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='domains.domain')),
                ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.tenant')),
            ],
            options={
                'db_table': 'domain_verifications',
            },
        ),
        migrations.AddConstraint(
            model_name='domain',
            constraint=models.UniqueConstraint(fields=('tenant', 'fqdn'), name='domains_tenant_fqdn_uniq'),
        ),
        migrations.AddConstraint(
            model_name='domain',
            constraint=models.UniqueConstraint(fields=('id', 'tenant'), name='domains_id_tenant_uniq'),
        ),
        migrations.AddConstraint(
            model_name='domain',
            constraint=models.UniqueConstraint(condition=models.Q(('status', 'verified')), fields=('fqdn',), name='domains_single_verified_owner'),
        ),
        migrations.AddConstraint(
            model_name='domain',
            constraint=models.CheckConstraint(condition=models.Q(('fqdn', django.db.models.functions.text.Lower('fqdn'))), name='domains_fqdn_lowercase'),
        ),
        migrations.AddConstraint(
            model_name='domain',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('status', 'verified'), _negated=True), models.Q(('reverify_due__isnull', False), ('verified_at__isnull', False), ('verified_method__gt', '')), _connector='OR'), name='domains_verified_fields_set'),
        ),
    ]
