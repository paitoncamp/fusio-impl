<?php

namespace Fusio\Impl\Migrations\Version;

use Doctrine\DBAL\Migrations\AbstractMigration;
use Doctrine\DBAL\Schema\Schema;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
class Version20180904200851 extends AbstractMigration
{
    /**
     * @param Schema $schema
     */
    public function up(Schema $schema)
    {
        $planTable = $schema->createTable('fusio_plan');
        $planTable->addColumn('id', 'integer', ['autoincrement' => true]);
        $planTable->addColumn('status', 'integer');
        $planTable->addColumn('name', 'string');
        $planTable->addColumn('description', 'string');
        $planTable->addColumn('price', 'decimal', ['precision' => 8, 'scale' => 2]);
        $planTable->addColumn('points', 'integer');
        $planTable->setPrimaryKey(['id']);

        $planTransactionTable = $schema->createTable('fusio_plan_transaction');
        $planTransactionTable->addColumn('id', 'integer', ['autoincrement' => true]);
        $planTransactionTable->addColumn('plan_id', 'integer');
        $planTransactionTable->addColumn('user_id', 'integer');
        $planTransactionTable->addColumn('status', 'integer');
        $planTransactionTable->addColumn('provider', 'string');
        $planTransactionTable->addColumn('transaction_id', 'string');
        $planTransactionTable->addColumn('amount', 'decimal', ['precision' => 8, 'scale' => 2]);
        $planTransactionTable->addColumn('insert_date', 'datetime');
        $planTransactionTable->setPrimaryKey(['id']);

        $planUsageTable = $schema->createTable('fusio_plan_usage');
        $planUsageTable->addColumn('id', 'integer', ['autoincrement' => true]);
        $planUsageTable->addColumn('route_id', 'integer');
        $planUsageTable->addColumn('user_id', 'integer');
        $planUsageTable->addColumn('app_id', 'integer');
        $planUsageTable->addColumn('action_id', 'integer');
        $planUsageTable->addColumn('points', 'integer');
        $planUsageTable->addColumn('insert_date', 'datetime');
        $planUsageTable->setPrimaryKey(['id']);
        $planUsageTable->addOption('engine', 'MyISAM');

        $userTable = $schema->getTable('fusio_user');
        $userTable->addColumn('points', 'integer');

        $routesTable = $schema->getTable('fusio_routes_method');
        $routesTable->addColumn('costs', 'integer');
    }

    /**
     * @param Schema $schema
     */
    public function down(Schema $schema)
    {
        // this down() migration is auto-generated, please modify it to your needs

    }
}
