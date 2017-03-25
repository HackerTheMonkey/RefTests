package org.techrefs.misc;

import bitronix.tm.BitronixTransactionManager;
import bitronix.tm.TransactionManagerServices;
import org.junit.Test;

import javax.transaction.HeuristicMixedException;
import javax.transaction.HeuristicRollbackException;
import javax.transaction.NotSupportedException;
import javax.transaction.RollbackException;
import javax.transaction.SystemException;

public class BitronixTest {

    @Test
    public void doSomething() throws SystemException, NotSupportedException, HeuristicRollbackException, HeuristicMixedException, RollbackException {

        System.out.println(TransactionManagerServices.getConfiguration().isWarnAboutZeroResourceTransaction());

        BitronixTransactionManager transactionManager = TransactionManagerServices.getTransactionManager();

        transactionManager.begin();

        new FooClass();

        transactionManager.commit();
    }

    private static class FooClass {

    }
}

