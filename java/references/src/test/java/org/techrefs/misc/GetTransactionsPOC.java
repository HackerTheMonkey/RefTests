package org.techrefs.misc;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import lombok.Data;
import org.junit.Test;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.StreamingOutput;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigDecimal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class GetTransactionsPOC {
    @Test
    public void get_transactions_from_DB_proof_of_concept() throws IOException {

        /**
         * Create a data source to our local mysql database.
         */
        DriverManagerDataSource dataSource = new org.springframework.jdbc.datasource.DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/MTA");
        dataSource.setUsername("root");
        dataSource.setPassword("secret");
        /**
         * Create a new instance of the JDBCTemplate with the default fetchSize
         * of 0
         *
         * NOTE: Here are are using the default fetchSize for MySQL JDBC Driver, which will
         * result in loading the entire query result set into memory.
         *
         * If we are going to run into potential OutOfMemoryErrors when processing large result sets
         * (e.g. millions of records), then we might need to consider altering the fetch size to Integer.MIN
         * and for that to happen we need to extend the JDBCTemplate as the default implementation doesn't
         * allow for nagative values, see EnhancedJDBCTemplate below.
         */
        final JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        jdbcTemplate.setFetchSize(0);
        /**
         * Create the CSV mapper for our domain model
         */
        final CsvMapper mapper = new CsvMapper();
        final CsvSchema schema = mapper.schemaFor(TransactionDetailsDAO.class).withHeader();
        mapper.addMixIn(TransactionDetailsDAO.class, CustomDateFormat.class);
        /**
         * Create the final StreamingOutput that is going to be used to stream
         * the response data back to our caller. From within it we are going to
         * iterate over the result set and stream one row at a time.
         */
        StreamingOutput stream = new StreamingOutput(){
            @Override
            public void write(OutputStream output) throws IOException, WebApplicationException {

                final BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(output));

                jdbcTemplate.query("select * from MTA.TRANSACTIONS", new RowCallbackHandler() {
                    @Override
                    public void processRow(ResultSet resultSet) throws SQLException {
                        try {

                            BeanPropertyRowMapper<TransactionDetailsDAO> mappedBean = new BeanPropertyRowMapper<TransactionDetailsDAO>(TransactionDetailsDAO.class);
                            TransactionDetailsDAO transactionDetailsDAO = mappedBean.mapRow(resultSet, resultSet.getRow());

                            String csvRow = mapper.writer(schema).writeValueAsString(transactionDetailsDAO);

                            bufferedWriter.write(csvRow);

                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                });

                bufferedWriter.flush();
            }
        };
        stream.write(System.out);
    }

    @Data
    public static class TransactionDetailsDAO{
        private String brandId = "MTA";
        private String appId = "1";
        private String cardType;
        private String maskedPAN;

        private Date today = new Date();


        private String approvalCode;

        private Long purchaseId;

        private BigDecimal transactionFeeAmount;

        private BigDecimal refundableAmount;

        private String responseCode;

        private String responseMessage;
    }

    private static class EnhancedJDBCTemplate extends JdbcTemplate{
        private EnhancedJDBCTemplate(DataSource dataSource) {
            super(dataSource);
        }

        private EnhancedJDBCTemplate(DataSource dataSource, boolean lazyInit) {
            super(dataSource, lazyInit);
        }

        @Override
        protected void applyStatementSettings(Statement stmt) throws SQLException {
            int fetchSize = getFetchSize();
            stmt.setFetchSize(fetchSize);
            int maxRows = getMaxRows();
            if (maxRows > 0) {
                stmt.setMaxRows(maxRows);
            }

            DataSourceUtils.applyTimeout(stmt, getDataSource(), getQueryTimeout());

        }
    }

    private static abstract  class CustomDateFormat{
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
        abstract Date getToday();
    }

    @Test
    public void playWithJackson() throws IOException {
        CsvMapper mapper = new CsvMapper();
        CsvSchema schemaWithHeader = mapper.schemaFor(Person.class).withHeader();
        CsvSchema schemaWithoutHeader = mapper.schemaFor(Person.class).withoutHeader();

        ArrayList<Person> persons = new ArrayList<Person>();
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());
        persons.add(new Person());

        BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(System.out));
        bufferedWriter.write(mapper.writer(schemaWithHeader).writeValueAsString(""));
        bufferedWriter.flush();

        for (Person person : persons) {
            bufferedWriter.write(mapper.writer(schemaWithoutHeader).writeValueAsString(person));
            bufferedWriter.flush();
        }
    }

    @Data
    private static class Person {
        private int age = 28;
        private String name = "hass";
    }
}
