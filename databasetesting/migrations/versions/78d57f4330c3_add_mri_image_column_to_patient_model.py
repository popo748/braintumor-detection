"""Add mri_image column to Patient model

Revision ID: 78d57f4330c3
Revises: 3a1f508d081b
Create Date: 2024-07-15 20:44:36.528840

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '78d57f4330c3'
down_revision = '3a1f508d081b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('patient', schema=None) as batch_op:
        batch_op.add_column(sa.Column('mri_image', sa.String(length=200), nullable=True))
        batch_op.drop_column('pituitary_image')
        batch_op.drop_column('glioma_image')
        batch_op.drop_column('meningioma_image')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('patient', schema=None) as batch_op:
        batch_op.add_column(sa.Column('meningioma_image', mysql.VARCHAR(length=200), nullable=True))
        batch_op.add_column(sa.Column('glioma_image', mysql.VARCHAR(length=200), nullable=True))
        batch_op.add_column(sa.Column('pituitary_image', mysql.VARCHAR(length=200), nullable=True))
        batch_op.drop_column('mri_image')

    # ### end Alembic commands ###
