"""book table

Revision ID: 7213fab051e6
Revises: 
Create Date: 2022-11-09 17:15:14.116761

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7213fab051e6'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('book',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=50), nullable=False),
    sa.Column('author', sa.String(length=50), nullable=False),
    sa.Column('pages', sa.Integer(), nullable=True),
    sa.Column('annum', sa.Integer(), nullable=True),
    sa.Column('date', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('book')
    # ### end Alembic commands ###
