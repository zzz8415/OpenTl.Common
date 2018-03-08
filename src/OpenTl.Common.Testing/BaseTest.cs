namespace OpenTl.Common.Testing
{
    using Castle.Windsor;

    public abstract class BaseTest
    {
        public abstract IWindsorContainer Container { get;} 
    }
}